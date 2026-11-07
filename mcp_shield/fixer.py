"""Auto-Fixer & Hardening Engine (`mcp-shield fix`).

Automatically hardens MCP configuration JSON files and strips invisible Unicode spoofing
or covert injection tags from skill/markdown files.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

from mcp_shield.scanners import DANGEROUS_FLAGS, SECRET_PATTERNS

UNICODE_SPOOF_RE = re.compile(r"[\u200b\u200c\u200d\u2060\u202a-\u202e\u2066-\u2069\ufeff]")


def harden_mcp_config_dict(config: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    """Return a hardened deep copy of an MCP config dictionary along with a list of applied fixes."""
    hardened = json.loads(json.dumps(config))
    fixes: List[str] = []

    servers = hardened.get("mcpServers") or hardened.get("servers") or {}
    if not isinstance(servers, dict):
        return hardened, fixes

    for server_name, server_cfg in servers.items():
        if not isinstance(server_cfg, dict):
            continue

        # 1. Remove -y / --yes and dangerous bypass flags from args
        args = server_cfg.get("args")
        if isinstance(args, list):
            new_args = []
            for a in args:
                a_str = str(a)
                if a_str in {"-y", "--yes"}:
                    fixes.append(f"[{server_name}] Removed auto-install flag '{a_str}' from args.")
                    continue
                if any(flag in a_str.lower() for flag in DANGEROUS_FLAGS):
                    fixes.append(f"[{server_name}] Removed dangerous permission bypass flag '{a_str}'.")
                    continue
                if a_str.strip() in {"/", "C:\\", "c:\\"}:
                    new_args.append("./workspace")
                    fixes.append(f"[{server_name}] Restricted root filesystem scope '{a_str}' to './workspace'.")
                    continue
                new_args.append(a)
            server_cfg["args"] = new_args

        # 2. Replace hardcoded secrets in env with ${ENV_VAR} references
        env_map = server_cfg.get("env")
        if isinstance(env_map, dict):
            for env_key, env_val in list(env_map.items()):
                val_str = str(env_val)
                if val_str.startswith("${") or val_str.startswith("$"):
                    continue
                is_secret = any(p.search(val_str) for _, _, p, _ in SECRET_PATTERNS) or bool(
                    re.search(r"(TOKEN|SECRET|PASSWORD|API_KEY|PRIVATE_KEY|URI)", env_key, re.IGNORECASE)
                )
                if is_secret:
                    env_map[env_key] = f"${{{env_key}}}"
                    fixes.append(
                        f"[{server_name}] Replaced hardcoded secret in 'env.{env_key}' with '${{{env_key}}}'."
                    )

        # 3. Upgrade plaintext HTTP remote URLs to HTTPS
        url = str(server_cfg.get("url", ""))
        if url.startswith("http://") and not ("localhost" in url or "127.0.0.1" in url):
            server_cfg["url"] = "https://" + url[len("http://") :]
            fixes.append(f"[{server_name}] Upgraded insecure remote URL to HTTPS: {server_cfg['url']}")

    return hardened, fixes


def sanitize_text_content(text: str) -> Tuple[str, List[str]]:
    """Strip invisible Unicode control characters from markdown/text files."""
    fixes: List[str] = []
    count = len(UNICODE_SPOOF_RE.findall(text))
    if count > 0:
        text = UNICODE_SPOOF_RE.sub("", text)
        fixes.append(f"Stripped {count} invisible/bidirectional Unicode spoofing character(s).")
    return text, fixes


def fix_file(target_path: Path, in_place: bool = False) -> Tuple[Path, List[str]]:
    """Apply automatic security hardening to an MCP JSON or Markdown file."""
    content = target_path.read_text(encoding="utf-8", errors="replace")
    out_path = target_path if in_place else target_path.with_name(f"{target_path.stem}.hardened{target_path.suffix}")

    if target_path.suffix.lower() == ".json":
        parsed = json.loads(content)
        hardened, fixes = harden_mcp_config_dict(parsed)
        out_path.write_text(json.dumps(hardened, indent=2) + "\n", encoding="utf-8")
        return out_path, fixes

    cleaned, fixes = sanitize_text_content(content)
    out_path.write_text(cleaned, encoding="utf-8")
    return out_path, fixes
