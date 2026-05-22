from __future__ import annotations
import re
from pathlib import Path
from typing import List, Optional, Tuple
from ..ir.graph import Send, Loc
from ..ir.types import Lattice, T, K

_ID   = r'[A-Za-z_$][A-Za-z0-9_$]*'
_CONT = re.compile(r'\bcontract\s+(' + _ID + r')\b')
_FN   = re.compile(r'\bfunction\s+(' + _ID + r')\s*\(')
_SEND = re.compile(r'\.sendMessageToL2\s*(?:\{([^}]*)\})?\s*\(([^;]{0,2000})\)', re.DOTALL)
_CANC = re.compile(r'\.startL1ToL2MessageCancellation\s*\(([^;]{0,1000})\)', re.DOTALL)
_PAY  = re.compile(r'\bpayable\b')
_MSGV = re.compile(r'\bmsg\.value\b')
_AC   = re.compile(r'\b(onlyOwner|onlyRole|require\s*\(\s*msg\.sender|_checkRole)\b')
_CAST = re.compile(r'\b(u?int(?:8|16|32|64|128|256)?|address|bool|bytes(?:32)?)\s*\(')


def _strip_comments(src: str) -> str:
    src = re.sub(r'/\*.*?\*/', lambda m: '\n' * m.group(0).count('\n'), src, flags=re.DOTALL)
    return re.sub(r'//[^\n]*', '', src)


def _split_args(s: str) -> List[str]:
    depth, cur, out = 0, [], []
    for ch in s:
        if ch in '([{': depth += 1; cur.append(ch)
        elif ch in ')]}': depth -= 1; cur.append(ch)
        elif ch == ',' and depth == 0: out.append(''.join(cur).strip()); cur = []
        else: cur.append(ch)
    if cur: out.append(''.join(cur).strip())
    return [a for a in out if a]


def _infer(expr: str) -> T:
    expr = expr.strip()
    m = _CAST.match(expr)
    if m: return Lattice.sol(m.group(1))
    low = expr.lower()
    if any(k in low for k in ('amount','value','qty','balance','fee','nonce')): return Lattice.sol('uint256')
    if any(k in low for k in ('recipient','sender','owner','addr')): return Lattice.sol('address')
    try: v = int(expr, 0); return Lattice.sol('uint256' if v > 0xFFFFFFFF else 'uint32')
    except ValueError: pass
    return T(K.UNK, name=expr[:40])


def _balanced(src: str, start: int) -> str:
    depth, i = 0, start
    while i < len(src):
        if src[i] == '{': depth += 1
        elif src[i] == '}':
            depth -= 1
            if depth == 0: return src[start:i+1]
        i += 1
    return src[start:]


class SolSourceParser:
    def __init__(self, src: str, fname: str = "?"):
        self._src  = _strip_comments(src)
        self._fname = fname

    @classmethod
    def load(cls, path: str) -> 'SolSourceParser':
        return cls(Path(path).read_text(encoding='utf-8', errors='replace'), path)

    def parse_sends(self) -> List[Send]:
        out = []
        for cm in _CONT.finditer(self._src):
            body = _balanced(self._src, self._src.find('{', cm.end()))
            off  = self._src.find('{', cm.end())
            for fm in _FN.finditer(body):
                bs = body.find('{', fm.end())
                if bs < 0: continue
                fb  = _balanced(body, bs)
                pay = bool(_PAY.search(body[fm.start():bs]))
                for sm in _SEND.finditer(fb):
                    args = _split_args(sm.group(2) or '')
                    if len(args) < 2: continue
                    try: sv = int(args[1], 0)
                    except ValueError: sv = None
                    out.append(Send(
                        contract=cm.group(1), fn=fm.group(1),
                        loc=Loc(self._fname, self._src[:off+bs+sm.start()].count('\n')+1),
                        to=args[0], sel_val=sv, sel_expr=args[1],
                        payload=[_infer(a) for a in args[2:]],
                        has_fee=bool(_MSGV.search(sm.group(1) or '')) or pay,
                    ))
        return out

    def parse_cancellations(self) -> List['CancellationCall']:
        out = []
        for cm in _CONT.finditer(self._src):
            body = _balanced(self._src, self._src.find('{', cm.end()))
            for fm in _FN.finditer(body):
                bs = body.find('{', fm.end())
                if bs < 0: continue
                fb = _balanced(body, bs)
                for xm in _CANC.finditer(fb):
                    out.append(CancellationCall(
                        contract=cm.group(1), fn=fm.group(1),
                        loc=Loc(self._fname, body[:bs+xm.start()].count('\n')+1),
                        has_access_control=bool(_AC.search(fb)),
                    ))
        return out


class CancellationCall:
    def __init__(self, contract: str, fn: str, loc: Loc, has_access_control: bool):
        self.contract = contract; self.fn = fn
        self.loc = loc; self.has_access_control = has_access_control
