import argparse, sys, os
from pathlib import Path
from .analysis.engine import Engine
from .config import AnalysisConfig
from .output.fmt import Fmt
from .output.sarif import SarifFormatter
from .output.html import HtmlFormatter

def main():
    ap = argparse.ArgumentParser(prog="crossguard",
        description="Cross-layer bridge security analyzer for Starknet")
    ap.add_argument("--version", action="version", version="crossguard 0.1.0-poc")
    sub = ap.add_subparsers(dest="cmd")

    a = sub.add_parser("analyze", help="Analyze an L1/L2 contract pair")
    a.add_argument("--l1", required=False)
    a.add_argument("--l2", required=False)
    a.add_argument("--config", default="crossguard.toml")
    a.add_argument("--format", dest="fmt",
                   choices=["terminal", "json", "sarif", "html"], default=None)
    a.add_argument("--output", "-o", default=None)
    a.add_argument("--fail-on", choices=["CRITICAL","HIGH","MEDIUM","LOW","NONE"], default=None)
    a.add_argument("--no-color", action="store_true")
    args = ap.parse_args()

    if args.cmd != "analyze":
        ap.print_help(); sys.exit(1)

    cfg = AnalysisConfig.load(args.config)
    l1 = args.l1 or cfg.l1
    l2 = args.l2 or cfg.l2
    fmt = args.fmt or cfg.output_format
    fail_on = args.fail_on or cfg.fail_on
    out_file = args.output or cfg.output_file
    color = not args.no_color and cfg.color

    if not l1 or not l2:
        print("error: --l1 and --l2 required (or set in crossguard.toml)", file=sys.stderr)
        sys.exit(4)
    for p, label in ((l1,"L1"),(l2,"L2")):
        if not os.path.exists(p):
            print(f"error: {label} file not found: {p}", file=sys.stderr); sys.exit(1)

    ctx = Engine().analyze(l1_path=l1, l2_path=l2)

    if fmt == "json":
        output = Fmt(color=False, as_json=True).render(ctx.findings, ctx.errors)
    elif fmt == "sarif":
        output = SarifFormatter().format(ctx.findings, ctx.errors)
    elif fmt == "html":
        output = HtmlFormatter().format(ctx.findings, ctx.errors, l1, l2)
    else:
        output = Fmt(color=color, as_json=False).render(ctx.findings, ctx.errors)

    if out_file:
        Path(out_file).write_text(output, encoding="utf-8")
        print(f"✓ Report written to {out_file}", file=sys.stderr)
    else:
        print(output)

    from .detectors.base import Sev
    sev_order = [s.value for s in Sev]
    if fail_on and fail_on != "NONE":
        idx = sev_order.index(fail_on)
        if any(sev_order.index(f.sev.value) <= idx for f in ctx.findings):
            sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    main()
