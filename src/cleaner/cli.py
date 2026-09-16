"""Command line entry point."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .files.base import Policy
from .pipeline import run
from .provenance.reseal import RESEAL_BLOCKED
from .text.hygiene import Options, scrub_text

DESCRIPTION = """\
Remove privacy-identifying metadata from your own files, and normalise invisible
characters out of text.

Files carrying C2PA Content Credentials are refused rather than scrubbed:
metadata is covered by the manifest's hard binding, so removing it would
invalidate the credentials.
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cleaner", description=DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    def add_file_args(p):
        p.add_argument("paths", nargs="+", type=Path)
        p.add_argument("-r", "--recursive", action="store_true")
        p.add_argument("--json", action="store_true", help="machine-readable output")
        p.add_argument("--strip-dates", action="store_true",
                       help="also remove creation and modification timestamps")
        p.add_argument("--strip-revisions", action="store_true",
                       help="anonymise tracked-change and comment authors (edits content)")

    inspect = sub.add_parser("inspect", help="report what is present; writes nothing")
    add_file_args(inspect)

    scrub = sub.add_parser("scrub", help="remove metadata")
    add_file_args(scrub)
    destination = scrub.add_mutually_exclusive_group()
    destination.add_argument("-o", "--output", type=Path, metavar="DIR")
    destination.add_argument("--in-place", action="store_true")
    scrub.add_argument("--reseal", action="store_true",
                       help=argparse.SUPPRESS)

    text = sub.add_parser("text", help="normalise invisible characters in text")
    text.add_argument("paths", nargs="*", type=Path,
                      help="files, or omit / use - for stdin")
    text.add_argument("--in-place", action="store_true")
    text.add_argument("--report", action="store_true",
                      help="list findings on stderr")
    text.add_argument("--keep-bidi", action="store_true",
                      help="retain bidirectional controls (Trojan Source risk)")
    text.add_argument("--ascii-punct", action="store_true",
                      help="fold smart quotes, dashes and ellipses to ASCII")
    text.add_argument("--strip-bom", action="store_true")
    text.add_argument("--normalize", choices=["nfc", "nfd", "nfkc", "nfkd"])
    text.add_argument("--encoding", default="utf-8")

    sub.add_parser("gui", help="launch the graphical interface")

    return parser


def _run_files(args, *, dry_run: bool) -> int:
    if getattr(args, "reseal", False):
        print(RESEAL_BLOCKED, file=sys.stderr)
        return 2

    policy = Policy(strip_dates=args.strip_dates, strip_revisions=args.strip_revisions)
    report = run(
        args.paths, policy,
        dry_run=dry_run,
        recursive=args.recursive,
        in_place=getattr(args, "in_place", False),
        output_dir=getattr(args, "output", None),
    )
    print(report.to_json() if args.json else report.to_text())
    return 1 if report.refused else 0


def _run_text(args) -> int:
    options = Options(
        keep_bidi=args.keep_bidi,
        ascii_punct=args.ascii_punct,
        normalize=args.normalize,
        strip_bom=args.strip_bom,
    )
    paths = [p for p in args.paths if str(p) != "-"]
    use_stdin = not paths

    if use_stdin:
        raw = sys.stdin.buffer.read()
        result = _scrub_bytes(raw, args.encoding, options)
        if result is None:
            return 1
        sys.stdout.buffer.write(result.text.encode(args.encoding))
        if args.report:
            _print_findings("<stdin>", result, args)
        return 0

    status = 0
    for path in paths:
        result = _scrub_bytes(path.read_bytes(), args.encoding, options, path)
        if result is None:
            status = 1
            continue
        if args.in_place:
            if result.changed:
                path.write_bytes(result.text.encode(args.encoding))
        else:
            sys.stdout.buffer.write(result.text.encode(args.encoding))
        if args.report:
            _print_findings(str(path), result, args)
    return status


def _scrub_bytes(raw: bytes, encoding: str, options: Options, path=None):
    try:
        # Decoded explicitly rather than opened as text: utf-8-sig would silently
        # consume the BOM that the Tier 1 rules need to reason about.
        text = raw.decode(encoding)
    except UnicodeDecodeError as exc:
        where = path or "<stdin>"
        print(f"cleaner: {where}: not valid {encoding} ({exc}); "
              f"use --encoding to override", file=sys.stderr)
        return None
    return scrub_text(text, options)


def _print_findings(label: str, result, args) -> None:
    changed = result.removed
    if not changed:
        print(f"{label}: nothing to change", file=sys.stderr)
        return
    print(f"{label}: {len(changed)} change(s)", file=sys.stderr)
    for finding in changed:
        print(f"  {finding}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "inspect":
        return _run_files(args, dry_run=True)
    if args.command == "scrub":
        return _run_files(args, dry_run=False)
    if args.command == "text":
        return _run_text(args)
    if args.command == "gui":
        from .gui import main as gui_main  # lazy: the CLI must not require tkinter
        return gui_main()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
