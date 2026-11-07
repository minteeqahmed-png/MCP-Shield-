"""Live MCP Server Dynamic Prober & Rug-Pull Lockfile Verifier."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Tuple

from mcp_shield.models import Finding, ScanResult, Severity
from mcp_shield.scanners import scan_text_for_poisoning


def compute_tool_fingerprint(tool_def: Dict[str, Any]) -> str:
    """Compute a deterministic SHA-256 fingerprint of an MCP tool schema."""
    canonical = json.dumps(tool_def, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def probe_stdio_mcp_server(
    command: str,
    args: List[str],
    env: Dict[str, str] | None = None,
    timeout_sec: float = 5.0,
) -> List[Dict[str, Any]]:
    """Spawn an MCP stdio server briefly to query its live `tools/list` schema."""
    init_req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "mcp-shield-probe", "version": "0.2.0"},
        },
    }
    list_req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
    stdin_payload = json.dumps(init_req) + "\n" + json.dumps(list_req) + "\n"

    proc = subprocess.run(
        [command, *args],
        input=stdin_payload,
        capture_output=True,
        text=True,
        timeout=timeout_sec,
        env=env,
        check=False,
    )

    tools: List[Dict[str, Any]] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("id") == 2 and "result" in msg:
            raw_tools = msg["result"].get("tools", [])
            if isinstance(raw_tools, list):
                tools.extend(t for t in raw_tools if isinstance(t, dict))
    return tools


def audit_and_lock_tools(
    server_name: str,
    tools: List[Dict[str, Any]],
    lockfile_path: Path | None = None,
) -> Tuple[List[Finding], Dict[str, str]]:
    """Scan live MCP tool schemas for poisoning and check against a lockfile for Rug-Pulls."""
    findings: List[Finding] = []
    current_hashes: Dict[str, str] = {}

    existing_lock: Dict[str, Dict[str, str]] = {}
    if lockfile_path and lockfile_path.exists():
        try:
            existing_lock = json.loads(lockfile_path.read_text(encoding="utf-8"))
        except Exception:
            existing_lock = {}

    server_locked = existing_lock.get(server_name, {})

    for tool in tools:
        t_name = str(tool.get("name", "unnamed"))
        fingerprint = compute_tool_fingerprint(tool)
        current_hashes[t_name] = fingerprint

        target_label = f"live-server:{server_name} -> tool:{t_name}"
        findings.extend(scan_text_for_poisoning(json.dumps(tool), target_label))

        # Check for Rug-Pull (schema mutation compared to lockfile)
        if t_name in server_locked and server_locked[t_name] != fingerprint:
            findings.append(
                Finding(
                    rule_id="RP-001",
                    category="MCP Rug-Pull Detection",
                    severity=Severity.CRITICAL,
                    title=f"Runtime Tool Schema Mutated ('{t_name}')",
                    description=(
                        f"The live tool schema for '{t_name}' on server '{server_name}' changed "
                        "since the lockfile was recorded—indicating a potential MCP rug-pull attack."
                    ),
                    target=target_label,
                    evidence=f"expected sha256:{server_locked[t_name][:12]} != actual sha256:{fingerprint[:12]}",
                    remediation="Inspect the updated tool description and inputSchema before re-locking.",
                )
            )

    if lockfile_path:
        existing_lock[server_name] = current_hashes
        lockfile_path.write_text(
            json.dumps(existing_lock, indent=2, sort_keys=True),
            encoding="utf-8",
        )

    return findings, current_hashes
