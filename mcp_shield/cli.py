"""Command-line interface for mcp-shield."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List

from mcp_shield import __version__
from mcp_shield.fixer import fix_file
from mcp_shield.mcp_server import run_stdio_server
from mcp_shield.models import ScanResult
from mcp_shield.prober import audit_and_lock_tools, probe_stdio_mcp_server
from mcp_shield.proxy import run_proxy_firewall
from mcp_shield.reporter import (
    export_html_report,
    export_json_report,
    export_sarif_report,
    format_terminal_report,
)
from mcp_shield.scanners import discover_default_mcp_configs, scan_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-shield",
        description="🛡️ mcp-shield: AI Agent & MCP Security Scanner, Prober, Auto-Fixer, and Runtime Firewall",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"mcp-shield {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command")

    # 1. scan command
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan files/directories (MCP configs, SKILL.md, Python MCP scripts) for security risks.",
    )
    scan_parser.add_argument(
        "target",
        nargs="?",
        default=".",
        help="Path to file or directory to scan (defaults to current directory).",
    )
    scan_parser.add_argument(
        "--json",
        dest="json_out",
        metavar="FILE",
        help="Export JSON report to the specified file path.",
    )
    scan_parser.add_argument(
        "--sarif",
        dest="sarif_out",
        metavar="FILE",
        help="Export SARIF v2.1.0 report for GitHub Security Code Scanning.",
    )
    scan_parser.add_argument(
        "--html",
        dest="html_out",
        metavar="FILE",
        help="Export interactive HTML security scorecard to the specified file path.",
    )
    scan_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color codes in terminal output.",
    )
    scan_parser.add_argument(
        "--fail-on-high",
        action="store_true",
        help="Return non-zero exit code (1) if HIGH or CRITICAL vulnerabilities are found.",
    )

    # 2. demo command
    demo_parser = subparsers.add_parser(
        "demo",
        help="Run mcp-shield against the built-in vulnerable MCP configs, skills, and AST examples.",
    )
    demo_parser.add_argument(
        "--html",
        dest="html_out",
        metavar="FILE",
        help="Optionally write the demo HTML dashboard to a file.",
    )
    demo_parser.add_argument(
        "--sarif",
        dest="sarif_out",
        metavar="FILE",
        help="Optionally write the demo SARIF report to a file.",
    )

    # 3. fix command
    fix_parser = subparsers.add_parser(
        "fix",
        help="Automatically harden an MCP config JSON or strip Unicode spoofing from a skill file.",
    )
    fix_parser.add_argument(
        "target",
        help="Path to the MCP config JSON or Markdown skill file to harden.",
    )
    fix_parser.add_argument(
        "--in-place",
        action="store_true",
        help="Overwrite the target file in place instead of creating a '.hardened' copy.",
    )

    # 4. probe command
    probe_parser = subparsers.add_parser(
        "probe",
        help="Dynamically spawn an MCP stdio server, inspect its live tools/list schemas, and verify lockfile hashes.",
    )
    probe_parser.add_argument(
        "--name",
        default="probed-server",
        help="Logical server name for lockfile tracking.",
    )
    probe_parser.add_argument(
        "--lockfile",
        default="mcp-shield.lock.json",
        help="Path to the SHA-256 tool schema lockfile for Rug-Pull detection.",
    )
    probe_parser.add_argument(
        "server_cmd",
        nargs=argparse.REMAINDER,
        help="Command and arguments to launch the MCP server (e.g., -- python -m mcp_shield serve).",
    )

    # 5. proxy command
    proxy_parser = subparsers.add_parser(
        "proxy",
        help="Wrap a downstream MCP stdio server in a real-time Man-in-the-Middle security firewall.",
    )
    proxy_parser.add_argument(
        "downstream_cmd",
        nargs=argparse.REMAINDER,
        help="Command and arguments for the downstream MCP server.",
    )

    # 6. discover command
    subparsers.add_parser(
        "discover",
        help="Auto-discover and scan standard local MCP configuration files on this machine.",
    )

    # 7. serve command (MCP stdio server)
    subparsers.add_parser(
        "serve",
        help="Run mcp-shield as a Model Context Protocol (MCP) stdio server for AI agents.",
    )

    return parser


def main(argv: List[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "serve":
        run_stdio_server()
        return 0

    if args.command == "fix":
        target_path = Path(args.target)
        if not target_path.exists():
            print(f"Error: file '{target_path}' not found.", file=sys.stderr)
            return 2
        out_path, fixes = fix_file(target_path, in_place=args.in_place)
        print(f"🛠️  Hardened file written to: {out_path}")
        for item in fixes:
            print(f"   ✔ {item}")
        if not fixes:
            print("   No automatic modifications were needed.")
        return 0

    if args.command == "probe":
        cmd_list = [c for c in args.server_cmd if c != "--"]
        if not cmd_list:
            print("Error: provide a server command after 'probe' (e.g. mcp-shield probe -- python -m mcp_shield serve)", file=sys.stderr)
            return 2
        tools = probe_stdio_mcp_server(cmd_list[0], cmd_list[1:])
        findings, hashes = audit_and_lock_tools(
            args.name, tools, lockfile_path=Path(args.lockfile)
        )
        res = ScanResult(scanned_targets=[f"live:{args.name} ({len(tools)} tools)"], findings=findings)
        print(format_terminal_report(res))
        print(f"🔒 Locked {len(hashes)} runtime tool fingerprint(s) to {args.lockfile}")
        return 0

    if args.command == "proxy":
        cmd_list = [c for c in args.downstream_cmd if c != "--"]
        return run_proxy_firewall(cmd_list)

    if args.command == "demo":
        repo_root = Path(__file__).resolve().parent.parent
        examples_dir = repo_root / "examples"
        if not examples_dir.exists():
            print(f"Examples directory not found at {examples_dir}", file=sys.stderr)
            return 1
        result = scan_path(examples_dir)
        print(format_terminal_report(result))
        if getattr(args, "html_out", None):
            out = Path(args.html_out)
            export_html_report(result, out)
            print(f"📊 HTML Security Scorecard written to: {out.resolve()}")
        if getattr(args, "sarif_out", None):
            out_sarif = Path(args.sarif_out)
            export_sarif_report(result, out_sarif)
            print(f"🛡️  SARIF v2.1.0 report written to: {out_sarif.resolve()}")
        return 0

    if args.command == "discover":
        configs = discover_default_mcp_configs()
        if not configs:
            print("No default local MCP config files found in standard locations.")
            return 0
        combined = ScanResult()
        for cfg in configs:
            sub = scan_path(cfg)
            combined.scanned_targets.extend(sub.scanned_targets)
            combined.findings.extend(sub.findings)
        print(format_terminal_report(combined))
        return 0

    # Default to `scan`
    target_str = getattr(args, "target", ".")
    target_path = Path(target_str)
    if not target_path.exists():
        print(f"Error: target path '{target_path}' does not exist.", file=sys.stderr)
        return 2

    result = scan_path(target_path)
    use_color = not getattr(args, "no_color", False)
    print(format_terminal_report(result, use_color=use_color))

    if getattr(args, "json_out", None):
        out_json = Path(args.json_out)
        export_json_report(result, out_json)
        print(f"📄 JSON report saved to: {out_json.resolve()}")

    if getattr(args, "sarif_out", None):
        out_sarif = Path(args.sarif_out)
        export_sarif_report(result, out_sarif)
        print(f"🛡️  SARIF report saved to: {out_sarif.resolve()}")

    if getattr(args, "html_out", None):
        out_html = Path(args.html_out)
        export_html_report(result, out_html)
        print(f"📊 HTML Security Scorecard saved to: {out_html.resolve()}")

    if getattr(args, "fail_on_high", False):
        counts = result.counts_by_severity()
        if counts["CRITICAL"] > 0 or counts["HIGH"] > 0:
            return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
