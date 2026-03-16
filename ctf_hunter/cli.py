"""
CTF Hunter — Command-Line Interface.

Provides headless analysis so CTF Hunter can be used without the GUI,
enabling scripted workflows, CI/CD pipelines, and integration with
other tools.

Usage examples:
    python main.py --cli file.bin
    python main.py --cli --depth deep --flag 'HTB\\{[^}]+\\}' challenge.png
    python main.py --cli --format json --output results.json *.bin
    python main.py --cli --depth auto --format markdown -o report.md folder/
"""
from __future__ import annotations

import argparse
import csv
import html
import io
import json
import os
import re
import sys
from pathlib import Path
from typing import List

from core.dispatcher import dispatch
from core.report import Finding


# ── Formatters ────────────────────────────────────────────────────────────

def _format_text(findings: List[Finding]) -> str:
    """Human-readable plain-text output."""
    if not findings:
        return "No findings.\n"
    lines: list[str] = []
    by_file: dict[str, list[Finding]] = {}
    for f in findings:
        by_file.setdefault(f.file, []).append(f)
    for fpath, flist in by_file.items():
        lines.append(f"{'=' * 72}")
        lines.append(f"File: {fpath}")
        lines.append(f"{'=' * 72}")
        for f in flist:
            if f.duplicate_of:
                continue
            flag = " [FLAG]" if f.flag_match else ""
            lines.append(f"  [{f.severity}] {f.title}{flag}  (conf: {f.confidence:.2f})")
            lines.append(f"    Analyzer: {f.analyzer}")
            if f.offset >= 0:
                lines.append(f"    Offset:   0x{f.offset:x}")
            if f.detail:
                detail = f.detail.replace("\n", "\n              ")
                lines.append(f"    Detail:   {detail}")
            lines.append("")
    return "\n".join(lines) + "\n"


def _format_json(findings: List[Finding]) -> str:
    """Machine-readable JSON output."""
    return json.dumps([f.to_dict() for f in findings if not f.duplicate_of], indent=2)


def _format_markdown(findings: List[Finding]) -> str:
    """Markdown report (mirrors GUI export)."""
    lines = ["# CTF Hunter Report\n"]
    by_file: dict[str, list[Finding]] = {}
    for f in findings:
        by_file.setdefault(f.file, []).append(f)
    for fpath, flist in by_file.items():
        lines.append(f"## {fpath}\n")
        for f in flist:
            if f.duplicate_of:
                continue
            flag_marker = " 🚩" if f.flag_match else ""
            lines.append(f"### [{f.severity}] {f.title}{flag_marker}")
            lines.append(f"- **Analyzer**: {f.analyzer}")
            lines.append(f"- **Confidence**: {f.confidence:.2f}")
            if f.offset >= 0:
                lines.append(f"- **Offset**: 0x{f.offset:x}")
            lines.append(f"- **Detail**: {f.detail}\n")
    return "\n".join(lines)


def _format_csv(findings: List[Finding]) -> str:
    """CSV output (mirrors GUI export)."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["ID", "File", "Analyzer", "Title", "Severity",
                      "Offset", "Confidence", "FlagMatch", "Detail"])
    for f in findings:
        writer.writerow([
            f.id, f.file, f.analyzer, f.title, f.severity,
            hex(f.offset) if f.offset >= 0 else "",
            f"{f.confidence:.2f}", str(f.flag_match), f.detail[:500],
        ])
    return buf.getvalue()


def _format_html(findings: List[Finding]) -> str:
    """Self-contained HTML report (mirrors GUI export)."""
    sev_color = {"HIGH": "#cc0000", "MEDIUM": "#886600", "LOW": "#004488", "INFO": "#333"}
    by_file: dict[str, list[Finding]] = {}
    for f in findings:
        by_file.setdefault(f.file, []).append(f)

    rows: list[str] = []
    for fpath, flist in by_file.items():
        rows.append(f"<h2>{html.escape(str(fpath))}</h2>")
        for f in flist:
            if f.duplicate_of:
                continue
            color = sev_color.get(f.severity, "#333")
            flag_icon = "🚩 " if f.flag_match else ""
            rows.append(
                f'<div style="border-left:4px solid {color};padding:8px;margin:8px 0;">'
                f'<b style="color:{color}">[{f.severity}]</b> {flag_icon}'
                f'<b>{html.escape(f.title)}</b> '
                f'<span style="color:#888">(conf: {f.confidence:.2f}, analyzer: {f.analyzer})</span>'
                f'<br><code>{html.escape(f.detail[:500])}</code>'
                f'</div>'
            )
    body = "\n".join(rows)
    return (
        "<!DOCTYPE html>\n"
        '<html><head><meta charset="utf-8"><title>CTF Hunter Report</title>\n'
        "<style>body{font-family:sans-serif;max-width:1200px;margin:auto;padding:20px}</style>\n"
        f"</head><body><h1>CTF Hunter Report</h1>{body}</body></html>"
    )


_FORMATTERS = {
    "text": _format_text,
    "json": _format_json,
    "markdown": _format_markdown,
    "csv": _format_csv,
    "html": _format_html,
}


# ── File collection ───────────────────────────────────────────────────────

def _collect_targets(paths: list[str]) -> list[str]:
    """Expand directories to their contained files (one level)."""
    targets: list[str] = []
    for p in paths:
        p = os.path.abspath(p)
        if os.path.isdir(p):
            for entry in sorted(os.listdir(p)):
                full = os.path.join(p, entry)
                if os.path.isfile(full):
                    targets.append(full)
        elif os.path.isfile(p):
            targets.append(p)
        else:
            print(f"Warning: skipping {p!r} (not a file or directory)", file=sys.stderr)
    return targets


# ── Argument parser ───────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ctf_hunter",
        description="CTF Hunter — automated CTF challenge file analyzer (CLI mode)",
    )
    parser.add_argument(
        "targets",
        nargs="+",
        help="Files or directories to analyze",
    )
    parser.add_argument(
        "--depth", "-d",
        choices=["fast", "deep", "auto"],
        default="fast",
        help="Analysis depth (default: fast)",
    )
    parser.add_argument(
        "--flag", "-f",
        default=r"CTF\{[^}]+\}",
        help="Flag regex pattern (default: CTF\\{[^}]+\\})",
    )
    parser.add_argument(
        "--format", "-F",
        choices=list(_FORMATTERS.keys()),
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Write output to file instead of stdout",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress progress messages on stderr",
    )
    parser.add_argument(
        "--flags-only",
        action="store_true",
        help="Only show findings that match the flag pattern",
    )
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=0.0,
        help="Minimum confidence threshold (0.0–1.0, default: 0.0)",
    )
    parser.add_argument(
        "--severity",
        choices=["HIGH", "MEDIUM", "LOW", "INFO"],
        default=None,
        help="Minimum severity filter",
    )
    return parser


# ── Main entry point ──────────────────────────────────────────────────────

_SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


def run_cli(argv: list[str] | None = None) -> int:
    """Run CTF Hunter in CLI mode.  Returns 0 on success, 1 on error."""
    parser = build_parser()
    args = parser.parse_args(argv)

    # Validate flag pattern
    try:
        flag_pattern = re.compile(args.flag, re.IGNORECASE)
    except re.error as exc:
        print(f"Error: invalid flag pattern: {exc}", file=sys.stderr)
        return 1

    # Collect targets
    targets = _collect_targets(args.targets)
    if not targets:
        print("Error: no files found to analyze.", file=sys.stderr)
        return 1

    # Analyze each file
    all_findings: list[Finding] = []
    for i, target in enumerate(targets, 1):
        if not args.quiet:
            print(f"[{i}/{len(targets)}] Analyzing {target} ({args.depth})...", file=sys.stderr)
        try:
            findings = dispatch(target, flag_pattern, args.depth)
            all_findings.extend(findings)
        except Exception as exc:
            print(f"Error analyzing {target}: {exc}", file=sys.stderr)

    # Apply filters
    if args.flags_only:
        all_findings = [f for f in all_findings if f.flag_match]

    if args.min_confidence > 0:
        all_findings = [f for f in all_findings if f.confidence >= args.min_confidence]

    if args.severity:
        min_sev = _SEVERITY_ORDER.get(args.severity, 3)
        all_findings = [f for f in all_findings
                        if _SEVERITY_ORDER.get(f.severity, 3) <= min_sev]

    # Sort: flags first, then by confidence descending
    all_findings.sort(
        key=lambda f: (not f.flag_match, -f.confidence, _SEVERITY_ORDER.get(f.severity, 3)),
    )

    # Format output
    formatter = _FORMATTERS[args.format]
    output = formatter(all_findings)

    # Write output
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output)
        if not args.quiet:
            print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(output, end="")

    # Summary on stderr
    if not args.quiet:
        flag_count = sum(1 for f in all_findings if f.flag_match)
        high_count = sum(1 for f in all_findings if f.severity == "HIGH" and not f.duplicate_of)
        print(
            f"\nDone: {len(all_findings)} findings, "
            f"{flag_count} flag(s), {high_count} HIGH severity",
            file=sys.stderr,
        )

    return 0
