"""Terminal scorecard, JSON, SARIF v2.1.0, and interactive HTML report generators for mcp-shield."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any, Dict, List

from mcp_shield import __version__
from mcp_shield.models import ScanResult, Severity


SEVERITY_COLORS = {
    Severity.CRITICAL: "\033[91;1m",  # Bright Red Bold
    Severity.HIGH: "\033[93;1m",      # Bright Yellow Bold
    Severity.MEDIUM: "\033[96m",      # Cyan
    Severity.LOW: "\033[94m",         # Blue
}
GRADE_COLORS = {
    "A": "\033[92;1m",
    "B": "\033[92m",
    "C": "\033[93;1m",
    "D": "\033[91m",
    "F": "\033[91;1m",
}
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"


def format_terminal_report(result: ScanResult, use_color: bool = True) -> str:
    """Format a rich terminal scorecard and findings table."""
    c_reset = RESET if use_color else ""
    c_bold = BOLD if use_color else ""
    c_dim = DIM if use_color else ""
    grade_color = GRADE_COLORS.get(result.grade, "") if use_color else ""

    counts = result.counts_by_severity()
    lines = [
        "",
        f"{c_bold}========================================================================{c_reset}",
        f"  🛡️  {c_bold}mcp-shield — AI Agent & MCP Security Scorecard{c_reset}",
        f"{c_bold}========================================================================{c_reset}",
        f"  Targets Scanned : {len(result.scanned_targets)}",
        f"  Security Score  : {grade_color}{result.score}/100 (Grade: {result.grade}){c_reset}",
        (
            f"  Findings Summary: "
            f"CRITICAL: {counts['CRITICAL']} | "
            f"HIGH: {counts['HIGH']} | "
            f"MEDIUM: {counts['MEDIUM']} | "
            f"LOW: {counts['LOW']}"
        ),
        f"{c_bold}------------------------------------------------------------------------{c_reset}",
    ]

    if not result.findings:
        lines.append(f"  ✅ {c_bold}No security issues detected! Your MCP & Agent setup looks clean.{c_reset}")
        lines.append(f"{c_bold}========================================================================{c_reset}\n")
        return "\n".join(lines)

    for idx, f in enumerate(result.findings, start=1):
        sev_col = SEVERITY_COLORS.get(f.severity, "") if use_color else ""
        lines.extend(
            [
                f"  [{idx}] {sev_col}[{f.severity.value}]{c_reset} {c_bold}{f.rule_id}: {f.title}{c_reset}",
                f"      Category   : {f.category}",
                f"      Target     : {c_dim}{f.target}{c_reset}",
                f"      Evidence   : {f.evidence}",
                f"      Remediation: {f.remediation}",
                "",
            ]
        )

    lines.append(f"{c_bold}========================================================================{c_reset}\n")
    return "\n".join(lines)


def export_json_report(result: ScanResult, output_path: Path) -> None:
    """Write scan results to a JSON file."""
    output_path.write_text(
        json.dumps(result.to_dict(), indent=2),
        encoding="utf-8",
    )


def export_sarif_report(result: ScanResult, output_path: Path) -> None:
    """Write scan results in SARIF v2.1.0 format for GitHub Code Scanning integration."""
    sarif_level_map = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
    }

    rules_index: Dict[str, Dict[str, Any]] = {}
    sarif_results: List[Dict[str, Any]] = []

    for f in result.findings:
        if f.rule_id not in rules_index:
            rules_index[f.rule_id] = {
                "id": f.rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "help": {"text": f.remediation},
                "properties": {"category": f.category, "security-severity": str(f.severity.weight)},
            }

        artifact_uri = f.target.split(" -> ")[0].split(":")[0].replace("\\", "/")
        sarif_results.append(
            {
                "ruleId": f.rule_id,
                "level": sarif_level_map.get(f.severity, "warning"),
                "message": {
                    "text": f"{f.title}: {f.description} (Evidence: {f.evidence}) Remediation: {f.remediation}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": artifact_uri},
                            "region": {"startLine": 1},
                        }
                    }
                ],
            }
        )

    sarif_doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "mcp-shield",
                        "version": __version__,
                        "informationUri": "https://github.com/minteeqahmed-png/MCP-Shield-",
                        "rules": list(rules_index.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }

    output_path.write_text(json.dumps(sarif_doc, indent=2), encoding="utf-8")


def export_html_report(result: ScanResult, output_path: Path) -> None:
    """Write a self-contained dark-mode HTML security dashboard."""
    counts = result.counts_by_severity()
    rows_html = []
    for f in result.findings:
        badge_class = f.severity.value.lower()
        rows_html.append(
            f"""
            <tr>
                <td><span class="badge {badge_class}">{html.escape(f.severity.value)}</span></td>
                <td><code>{html.escape(f.rule_id)}</code></td>
                <td><strong>{html.escape(f.title)}</strong><div class="desc">{html.escape(f.description)}</div></td>
                <td><code>{html.escape(f.target)}</code></td>
                <td><code>{html.escape(f.evidence)}</code></td>
                <td>{html.escape(f.remediation)}</td>
            </tr>
            """
        )

    findings_table = (
        "\n".join(rows_html)
        if rows_html
        else '<tr><td colspan="6" style="text-align:center;">No findings detected!</td></tr>'
    )

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>mcp-shield Security Report</title>
<style>
  body {{ font-family: system-ui, -apple-system, sans-serif; background: #0d1117; color: #e6edf3; margin: 2rem; }}
  .header {{ display: flex; justify-content: space-between; align-items: center; background: #161b22; padding: 1.5rem; border-radius: 10px; border: 1px solid #30363d; }}
  .grade {{ font-size: 2.5rem; font-weight: 800; padding: 0.5rem 1.2rem; border-radius: 8px; background: #21262d; }}
  .stats {{ display: flex; gap: 1rem; margin: 1.5rem 0; }}
  .card {{ background: #161b22; border: 1px solid #30363d; padding: 1rem 1.5rem; border-radius: 8px; flex: 1; }}
  table {{ width: 100%; border-collapse: collapse; background: #161b22; border-radius: 8px; overflow: hidden; }}
  th, td {{ padding: 0.85rem 1rem; text-align: left; border-bottom: 1px solid #30363d; font-size: 0.9rem; }}
  th {{ background: #21262d; color: #8b949e; text-transform: uppercase; font-size: 0.78rem; }}
  .desc {{ color: #8b949e; font-size: 0.82rem; margin-top: 0.25rem; }}
  .badge {{ padding: 0.2rem 0.55rem; border-radius: 4px; font-weight: 700; font-size: 0.75rem; }}
  .critical {{ background: #da3633; color: #fff; }}
  .high {{ background: #d29922; color: #000; }}
  .medium {{ background: #1f6feb; color: #fff; }}
  .low {{ background: #388bfd33; color: #58a6ff; }}
  code {{ background: #21262d; padding: 0.15rem 0.35rem; border-radius: 4px; font-size: 0.82rem; }}
</style>
</head>
<body>
  <div class="header">
    <div>
      <h1 style="margin:0;">🛡️ mcp-shield Security Scorecard</h1>
      <p style="margin:0.4rem 0 0;color:#8b949e;">Scanned {len(result.scanned_targets)} target(s)</p>
    </div>
    <div class="grade">Score: {result.score}/100 ({html.escape(result.grade)})</div>
  </div>
  <div class="stats">
    <div class="card"><strong>CRITICAL</strong><h2>{counts['CRITICAL']}</h2></div>
    <div class="card"><strong>HIGH</strong><h2>{counts['HIGH']}</h2></div>
    <div class="card"><strong>MEDIUM</strong><h2>{counts['MEDIUM']}</h2></div>
    <div class="card"><strong>LOW</strong><h2>{counts['LOW']}</h2></div>
  </div>
  <table>
    <thead>
      <tr>
        <th>Severity</th>
        <th>Rule</th>
        <th>Finding</th>
        <th>Target</th>
        <th>Evidence</th>
        <th>Remediation</th>
      </tr>
    </thead>
    <tbody>
      {findings_table}
    </tbody>
  </table>
</body>
</html>"""
    output_path.write_text(doc, encoding="utf-8")
