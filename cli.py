import argparse, sys, os
from .analysis.engine import Engine
from .output.fmt import Fmt


def main():
    ap = argparse.ArgumentParser(prog="crossguard")
    sub = ap.add_subparsers(dest="cmd")
    a = sub.add_parser("analyze")
    a.add_argument("--l1", required=True)
    a.add_argument("--l2", required=True)
    a.add_argument("--json",     action="store_true")
    a.add_argument("--no-color", action="store_true")
    args = ap.parse_args()

    if args.cmd != "analyze":
        ap.print_help(); sys.exit(1)

    for p, label in ((args.l1, "L1"), (args.l2, "L2")):
        if not os.path.exists(p):
            print(f"error: {label} file not found: {p}", file=sys.stderr); sys.exit(1)

    ctx = Engine().analyze(l1_path=args.l1, l2_path=args.l2)
    print(Fmt(color=not args.no_color, as_json=args.json).render(ctx.findings, ctx.errors))
    sys.exit(1 if ctx.critical else 0)


if __name__ == "__main__":
    main()
