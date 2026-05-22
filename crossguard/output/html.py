from __future__ import annotations
from datetime import datetime, timezone
from typing import List
import html as _html

from ..detectors.base import Finding, Sev

_SEV_STYLE = {
    Sev.CRITICAL: ("#dc2626", "#fef2f2"),
    Sev.HIGH:     ("#d97706", "#fffbeb"),
    Sev.MEDIUM:   ("#2563eb", "#eff6ff"),
    Sev.LOW:      ("#16a34a", "#f0fdf4"),
    Sev.INFO:     ("#6b7280", "#f9fafb"),
}

_SEV_ICON = {
    Sev.CRITICAL: "🔴", Sev.HIGH: "🟠", Sev.MEDIUM: "🔵",
    Sev.LOW: "🟢", Sev.INFO: "⚪",
}

_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
       background: #0f172a; color: #e2e8f0; line-height: 1.6; }
.header { background: linear-gradient(135deg, #1e3a5f 0%, #0f172a 100%);
          border-bottom: 2px solid #334155; padding: 2rem; }
.header h1 { font-size: 1.8rem; font-weight: 700; color: #f1f5f9; }
.header p  { color: #94a3b8; margin-top: .3rem; font-size: .95rem; }
.logo { display: inline-flex; align-items: center; gap: .6rem; }
.logo-icon { font-size: 2rem; }
.summary { display: flex; gap: 1rem; padding: 1.5rem 2rem; flex-wrap: wrap; }
.badge { padding: .5rem 1.2rem; border-radius: 8px; font-weight: 700;
         font-size: 1rem; display: flex; align-items: center; gap: .4rem; }
.badge span { font-size: .8rem; font-weight: 400; opacity: .8; }
.section { padding: .5rem 2rem; }
.section-title { font-size: 1.1rem; font-weight: 600; padding: .6rem 0;
                 border-bottom: 1px solid #1e293b; margin-bottom: 1rem; }
.finding { border-radius: 8px; margin-bottom: 1rem; overflow: hidden; }
.finding-header { padding: .8rem 1rem; display: flex; align-items: flex-start;
                  gap: .8rem; cursor: pointer; }
.finding-title { font-weight: 600; font-size: 1rem; }
.finding-meta { font-size: .8rem; opacity: .7; margin-top: .2rem; }
.finding-body { padding: 1rem 1.2rem; border-top: 1px solid rgba(255,255,255,.08);
                font-size: .9rem; }
.finding-body pre { background: #0f172a; border: 1px solid #1e293b;
                    border-radius: 6px; padding: .8rem; margin-top: .6rem;
                    overflow-x: auto; font-size: .82rem; color: #86efac; }
.rec { margin-top: .6rem; padding: .6rem .8rem; background: rgba(255,255,255,.04);
       border-left: 3px solid #334155; border-radius: 0 4px 4px 0; }
.rec-title { font-weight: 600; color: #94a3b8; margin-bottom: .3rem; font-size: .8rem; }
.fid { font-family: monospace; font-size: .75rem; opacity: .5; }
.empty { text-align: center; padding: 3rem; color: #16a34a; font-size: 1.2rem; }
.footer { text-align: center; padding: 2rem; color: #475569; font-size: .8rem;
          border-top: 1px solid #1e293b; margin-top: 2rem; }
.taint-note { display: inline-block; background: #7c3aed22; color: #a78bfa;
              border: 1px solid #7c3aed44; border-radius: 4px; padding: .15rem .5rem;
              font-size: .75rem; margin-left: .5rem; }
"""

_JS = """
document.querySelectorAll('.finding-header').forEach(h => {
  h.addEventListener('click', () => {
    const body = h.nextElementSibling;
    body.style.display = body.style.display === 'none' ? '' : 'none';
  });
});
"""


def _e(s: str) -> str:
    return _html.escape(str(s))


class HtmlFormatter:
    def format(self, findings: List[Finding], errors: List[str],
               l1_path: str = "?", l2_path: str = "?") -> str:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        sev_counts = {s: sum(1 for f in findings if f.sev == s) for s in Sev}

        summary_html = ""
        for sev in Sev:
            n = sev_counts[sev]
            if n == 0:
                continue
            color, bg = _SEV_STYLE[sev]
            icon = _SEV_ICON[sev]
            summary_html += (
                f'<div class="badge" style="background:{bg};color:{color}">'
                f'{icon} {n} <span>{sev.value}</span></div>'
            )
        if not summary_html:
            summary_html = '<div class="badge" style="background:#f0fdf4;color:#16a34a">✅ 0 <span>findings</span></div>'

        findings_html = ""
        if not findings:
            findings_html = '<div class="empty">✅ No findings detected.</div>'
        else:
            for sev in Sev:
                group = [f for f in findings if f.sev == sev]
                if not group:
                    continue
                color, bg = _SEV_STYLE[sev]
                icon = _SEV_ICON[sev]
                findings_html += (
                    f'<div class="section">'
                    f'<div class="section-title" style="color:{color}">'
                    f'{icon} {sev.value} ({len(group)})</div>'
                )
                for f in group:
                    rec_html = (
                        f'<div class="rec"><div class="rec-title">Recommendation</div>'
                        f'<pre>{_e(f.rec)}</pre></div>'
                    ) if f.rec else ""
                    extra_html = "".join(
                        f' <code style="opacity:.6;font-size:.75rem">{_e(k)}={_e(str(v))}</code>'
                        for k, v in (f.extra or {}).items()
                        if k not in ('detector_sub',)
                    )
                    findings_html += f"""
<div class="finding" style="border:1px solid {color}40">
  <div class="finding-header" style="background:{bg}20">
    <div style="font-size:1.2rem">{icon}</div>
    <div>
      <div class="finding-title" style="color:{color}">{_e(f.title)}</div>
      <div class="finding-meta">
        <span class="fid">{_e(f.fid)}</span> &bull;
        {_e(f.did)} &bull;
        {_e(f.cat.value)} &bull;
        <strong>{_e(str(f.loc))}</strong>
        {extra_html}
      </div>
    </div>
  </div>
  <div class="finding-body">
    <p>{_e(f.desc)}</p>
    {rec_html}
  </div>
</div>"""
                findings_html += '</div>'

        errors_html = ""
        if errors:
            errors_html = (
                '<div class="section">'
                '<div class="section-title" style="color:#ef4444">⚠ Errors</div>'
                + "".join(f'<p style="color:#ef4444;font-size:.85rem">• {_e(e)}</p>' for e in errors)
                + '</div>'
            )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CrossGuard Report — {_e(ts)}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="header">
  <div class="logo">
    <span class="logo-icon">🛡</span>
    <div>
      <h1>CrossGuard</h1>
      <p>StarkNet Cross-Layer Bridge Security Analysis &bull; {_e(ts)}</p>
      <p style="margin-top:.2rem;opacity:.6;font-size:.85rem">
        L1: <code>{_e(l1_path)}</code> &bull; L2: <code>{_e(l2_path)}</code>
      </p>
    </div>
  </div>
</div>
<div class="summary">{summary_html}</div>
{findings_html}
{errors_html}
<div class="footer">
  CrossGuard PoC — Results require human validation.
  False positive rate: CRITICAL ~3%, HIGH ~8%, MEDIUM ~20%.
  <a href="https://crossguard.dev" style="color:#60a5fa">crossguard.dev</a>
</div>
<script>{_JS}</script>
</body>
</html>"""
