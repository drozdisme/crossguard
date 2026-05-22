from __future__ import annotations
import re
from pathlib import Path
from typing import List, Optional
from ..ir.graph import Handler, Param, Loc
from ..ir.types import Lattice, K
from ..analysis.selector import sn_keccak

_L1_ATTR = re.compile(r'#\[l1_handler\]')
_FN      = re.compile(r'\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(')
_PARAM   = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([A-Za-z0-9_:,<>\s]+?)(?=[,)])')
_MOD     = re.compile(r'mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{')
_ASSERT  = re.compile(r'\bassert[!?(]')
_FROM    = re.compile(r'\bfrom_address\b')
_EQ      = re.compile(r'from_address\s*==|==\s*from_address')
_SINK    = re.compile(r'\b(transfer|mint|burn|withdraw|send_message_to_l1_syscall|emit)\s*[\(!(]')
_STORE   = re.compile(r'self\.\w+\.read\(\)')
_SEND_L1 = re.compile(r'\bsend_message_to_l1_syscall\b')
_NONCE   = re.compile(r'\b(nonce|serial|consumed|processed)\b')


def _balanced(src: str, start: int) -> str:
    depth, i = 0, start
    while i < len(src):
        if src[i] == '{': depth += 1
        elif src[i] == '}':
            depth -= 1
            if depth == 0: return src[start:i+1]
        i += 1
    return src[start:]


def _strip_comments(src: str) -> str:
    return re.sub(r'//[^\n]*', '', src)


class TaintResult:
    VERIFIED = "verified"; UNVERIFIED = "unverified"; PARTIAL = "partial"

    def __init__(self, status: str, has_sink: bool, note: str = ""):
        self.status = status; self.has_sink = has_sink; self.note = note

    @property
    def is_verified(self) -> bool:
        return self.status == self.VERIFIED


class CaiSourceParser:
    def __init__(self, src: str, fname: str = "?"):
        self._src   = _strip_comments(src)
        self._fname = fname

    @classmethod
    def load(cls, path: str) -> 'CaiSourceParser':
        return cls(Path(path).read_text(encoding='utf-8', errors='replace'), path)

    def parse(self) -> List[Handler]:
        out, src = [], self._src
        mod = next((m.group(1) for m in _MOD.finditer(src)), self._fname.split('/')[-1].split('.')[0])
        i = 0
        while i < len(src):
            am = _L1_ATTR.search(src, i)
            if not am: break
            fm = _FN.search(src, am.end())
            if not fm: i = am.end(); continue
            bs = src.find('{', fm.end())
            if bs < 0: i = fm.end(); continue
            body  = _balanced(src, bs)
            pe    = src.find(')', fm.end())
            params = self._params(src[fm.end():pe] if pe > 0 else '')
            line   = src[:fm.start()].count('\n') + 1
            taint  = self._taint(body)
            h = Handler(contract=mod, fn=fm.group(1),
                        loc=Loc(self._fname, line),
                        sel=sn_keccak(fm.group(1)),
                        params=params, checked=taint.is_verified)
            h._taint = taint  # type: ignore[attr-defined]
            h._body  = body   # type: ignore[attr-defined]
            out.append(h)
            i = am.end()
        return out

    def _params(self, raw: str) -> List[Param]:
        out = []
        for m in _PARAM.finditer(raw):
            n, t = m.group(1).strip(), m.group(2).strip().rstrip(',')
            if n in ('self', 'ref'): continue
            out.append(Param(name=n, typ=Lattice.cai(t), raw=t))
        return out

    def _taint(self, body: str) -> TaintResult:
        has_sink = bool(_SINK.search(body))
        if not _FROM.search(body):
            return TaintResult(TaintResult.UNVERIFIED, has_sink)
        if not _ASSERT.search(body) and not _EQ.search(body):
            return TaintResult(TaintResult.UNVERIFIED, has_sink)
        # assert present — check ordering vs sink
        al = self._first(_ASSERT, body)
        sl = self._first(_SINK, body)
        if has_sink and al is not None and sl is not None and al > sl:
            return TaintResult(TaintResult.PARTIAL, True, "assert follows sink")
        return TaintResult(TaintResult.VERIFIED, has_sink)

    @staticmethod
    def _first(pat: re.Pattern, text: str) -> Optional[int]:
        m = pat.search(text)
        return text[:m.start()].count('\n') if m else None
