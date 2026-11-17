"""CycloneDX v1.5 Software Bill of Materials (SBOM) & MCP Server Inventory Generator."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Dict, List

from mcp_shield import __version__


def _extract_pkg_and_version(command: str, args: List[str]) -> tuple[str, str]:
    """Extract package name and version pin from MCP server command and args."""
    non_flags = [a for a in args if not a.startswith("-")]
    if command in {"npx", "uvx", "pipx", "bunx"} and non_flags:
        spec = non_flags[0]
        if "==" in spec:
            name, ver = spec.split("==", 1)
            return name, ver
        match = re.match(r"^(@?[^@]+)@([0-9][^\s]*)$", spec)
        if match:
            return match.group(1), match.group(2)
        return spec, "unpinned"
    if non_flags:
        return non_flags[0], "local-script"
    return command or "remote-endpoint", "n/a"


def generate_mcp_sbom(target_path: Path) -> Dict[str, Any]:
    """Scan a file or directory of MCP configs and build a CycloneDX v1.5 JSON SBOM."""
    config_files: List[Path] = []
    if target_path.is_file():
        config_files.append(target_path)
    elif target_path.is_dir():
        config_files.extend(sorted(target_path.rglob("*.json")))

    components: List[Dict[str, Any]] = []
    for cfg_file in config_files:
        try:
            parsed = json.loads(cfg_file.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        if not isinstance(parsed, dict):
            continue
        servers = parsed.get("mcpServers") or parsed.get("servers")
        if not isinstance(servers, dict):
            continue

        for srv_name, srv_cfg in servers.items():
            if not isinstance(srv_cfg, dict):
                continue
            command = str(srv_cfg.get("command", "")).strip()
            args = [str(a) for a in srv_cfg.get("args", []) if a is not None]
            url = str(srv_cfg.get("url", "")).strip()
            env_keys = sorted((srv_cfg.get("env") or {}).keys()) if isinstance(srv_cfg.get("env"), dict) else []
            tools = srv_cfg.get("tools") or []
            tool_names = [t.get("name", "unnamed") for t in tools if isinstance(t, dict)]

            pkg_name, pkg_version = _extract_pkg_and_version(command, args)
            transport = "sse/http" if url else "stdio"
            comp_id = hashlib.sha256(f"{cfg_file}:{srv_name}:{pkg_name}".encode("utf-8")).hexdigest()[:16]

            components.append(
                {
                    "type": "application",
                    "bom-ref": f"mcp-server-{srv_name}-{comp_id}",
                    "name": srv_name,
                    "version": pkg_version,
                    "description": f"MCP Server '{srv_name}' ({pkg_name}) configured in {cfg_file.name}",
                    "properties": [
                        {"name": "mcp:source_file", "value": str(cfg_file)},
                        {"name": "mcp:runtime_command", "value": command or "remote"},
                        {"name": "mcp:package_identifier", "value": pkg_name},
                        {"name": "mcp:version_pinned", "value": str(pkg_version not in {"unpinned", "n/a", "local-script"}).lower()},
                        {"name": "mcp:transport", "value": transport},
                        {"name": "mcp:env_vars_referenced", "value": ", ".join(env_keys) if env_keys else "none"},
                        {"name": "mcp:declared_tools", "value": ", ".join(tool_names) if tool_names else "dynamic"},
                    ],
                }
            )

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [
                {
                    "vendor": "mcp-shield",
                    "name": "mcp-shield-sbom-generator",
                    "version": __version__,
                }
            ],
        },
        "components": components,
    }


def format_sbom_table(sbom: Dict[str, Any]) -> str:
    """Format a human-readable terminal table of discovered MCP server components."""
    comps = sbom.get("components", [])
    lines = [
        "=" * 78,
        "  📦 mcp-shield — MCP Software Bill of Materials (CycloneDX v1.5 Inventory)",
        "=" * 78,
        f"  Total MCP Servers Inventoried: {len(comps)}",
        "-" * 78,
        f"  {'SERVER NAME':<22} | {'RUNTIME / PACKAGE':<30} | {'VERSION':<10} | {'TRANSPORT'}",
        "-" * 78,
    ]
    for c in comps:
        props = {p["name"]: p["value"] for p in c.get("properties", [])}
        pkg = props.get("mcp:package_identifier", c["name"])
        if len(pkg) > 28:
            pkg = pkg[:25] + "..."
        lines.append(
            f"  {c['name'][:22]:<22} | {pkg:<30} | {c['version'][:10]:<10} | {props.get('mcp:transport', 'stdio')}"
        )
    lines.append("=" * 78)
    return "\n".join(lines)
