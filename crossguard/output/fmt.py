from __future__ import annotations
import json
from typing import List
from ..detectors.base import Finding, Sev

_C = {
    "CRITICAL": "\033[91m", "HIGH": "\033[93m", "MEDIUM": "\033[94m",
    "LOW": "\033[96m", "INFO": "\033[97m",
    "R": "\033[0m", "B": "\033[1m", "D": "\033[2m", "G": "\033[92m",
}
_NO = {k: "" for k in _C}


class Fmt:
    def __init__(self, color=True, as_json=False):
        self.c = _C if color else _NO
        self.json = as_json

    def render(self, findings: List[Finding], errors: List[str]) -> str:
        return self._json(findings, errors) if self.json else self._term(findings, errors)

    def _json(self, ff, ee):
        return json.dumps({
            "version": "0.1.0-poc",
            "summary": {s.value.lower(): sum(1 for f in ff if f.sev == s) for s in Sev},
            "total": len(ff),
            "findings": [f.to_dict() for f in ff],
            "errors": ee,
        }, indent=2)

    def _term(self, ff, ee):
        c = self.c
        lines = [
            f"\n{c['B']}╔══════════════════════════════════════╗{c['R']}",
            f"{c['B']}║  CrossGuard — StarkNet Bridge Audit  ║{c['R']}",
            f"{c['B']}╚══════════════════════════════════════╝{c['R']}\n",
        ]
        if not ff:
            lines.append(f"{c['G']}✓ No findings.{c['R']}\n")
            return "\n".join(lines)

        for sev in (Sev.CRITICAL, Sev.HIGH, Sev.MEDIUM, Sev.LOW, Sev.INFO):
            group = [f for f in ff if f.sev == sev]
            if not group: continue
            sc = c.get(sev.value, "")
            lines.append(f"{sc}{c['B']}━━━ {sev.value} ({len(group)}) ━━━{c['R']}")
            for f in group:
                lines += [
                    f"\n  {sc}{c['B']}[{f.fid}] {f.title}{c['R']}",
                    f"  {c['D']}detector:{c['R']} {f.did}",
                    f"  {c['D']}location:{c['R']} {c['B']}{f.loc}{c['R']}",
                    f"  {c['D']}category:{c['R']} {f.cat.value}",
                    f"\n  {f.desc}",
                ]
                if f.rec:
                    lines.append(f"\n  {c['D']}fix:{c['R']}")
                    lines += [f"    {l}" for l in f.rec.splitlines()]
                lines.append("")

        nc = sum(1 for f in ff if f.sev == Sev.CRITICAL)
        nh = sum(1 for f in ff if f.sev == Sev.HIGH)
        lines.append(
            f"\n{c['B']}Total:{c['R']} {len(ff)}  "
            f"{c['CRITICAL']}{nc} CRITICAL{c['R']}  {c['HIGH']}{nh} HIGH{c['R']}"
        )
        if ee:
            lines += [f"\n{c['HIGH']}Errors:{c['R']}"] + [f"  • {e}" for e in ee]
        return "\n".join(lines)
