"""Declarative security policy engine and allowlist validator for MCP configurations."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

from mcp_shield.models import Finding, Severity

DEFAULT_POLICY: Dict[str, Any] = {
    "version": "1.0",
    "organization": "default-mcp-shield-policy",
    "allowed_commands": ["npx", "uvx", "python", "python3", "node", "docker"],
    "allowed_package_prefixes": [
        "@modelcontextprotocol/",
        "mcp-server-",
        "mcp_shield",
    ],
    "blocked_domains": [
        "webhook.site",
        "requestbin.com",
        "ngrok-free.app",
        "burpcollaborator.net",
        "interact.sh",
    ],
    "require_env_placeholders": True,
    "require_https_transport": True,
}


def write_default_policy(output_path: Path) -> Path:
    """Write a starter mcp-shield-policy.json file to disk."""
    output_path.write_text(json.dumps(DEFAULT_POLICY, indent=2) + "\n", encoding="utf-8")
    return output_path


def load_policy(policy_path: Path | None = None) -> Dict[str, Any]:
    """Load a custom JSON security policy or return DEFAULT_POLICY."""
    if policy_path is None or not policy_path.exists():
        return dict(DEFAULT_POLICY)
    raw = json.loads(policy_path.read_text(encoding="utf-8"))
    merged = dict(DEFAULT_POLICY)
    if isinstance(raw, dict):
        merged.update(raw)
    return merged


def evaluate_config_against_policy(
    config: Dict[str, Any],
    policy: Dict[str, Any],
    source_label: str = "mcp.json",
) -> List[Finding]:
    """Validate an MCP configuration dictionary against a declarative security policy."""
    findings: List[Finding] = []
    servers = config.get("mcpServers") or config.get("servers") or {}
    if not isinstance(servers, dict):
        return findings

    allowed_cmds = {str(c).lower() for c in policy.get("allowed_commands", [])}
    allowed_prefixes = tuple(str(p) for p in policy.get("allowed_package_prefixes", []))
    blocked_domains = [str(d).lower() for d in policy.get("blocked_domains", [])]
    require_placeholders = bool(policy.get("require_env_placeholders", True))
    require_https = bool(policy.get("require_https_transport", True))

    for server_name, server_cfg in servers.items():
        if not isinstance(server_cfg, dict):
            continue
        target = f"{source_label} -> server:{server_name}"
        command = str(server_cfg.get("command", "")).strip()
        args = [str(a) for a in server_cfg.get("args", []) if a is not None]
        env_map = server_cfg.get("env") or {}
        url = str(server_cfg.get("url", "")).strip()

        # POL-001: Disallowed runtime binary
        if command and allowed_cmds and Path(command).stem.lower() not in allowed_cmds:
            findings.append(
                Finding(
                    rule_id="POL-001",
                    category="Policy Violation",
                    severity=Severity.HIGH,
                    title="Disallowed MCP Server Runtime Command",
                    description=(
                        f"Server '{server_name}' invokes '{command}', which is not in the policy "
                        f"allowlist ({sorted(allowed_cmds)})."
                    ),
                    target=target,
                    evidence=f"command: {command}",
                    remediation="Use an approved runtime binary or add the binary to mcp-shield-policy.json.",
                )
            )

        # POL-002: Blocked external domain in args, url, or tool descriptions
        serialized_srv = json.dumps(server_cfg).lower()
        for domain in blocked_domains:
            if domain and domain in serialized_srv:
                findings.append(
                    Finding(
                        rule_id="POL-002",
                        category="Policy Violation",
                        severity=Severity.CRITICAL,
                        title="Blocked External Domain Referenced in MCP Server",
                        description=(
                            f"Server '{server_name}' references blocked domain '{domain}' prohibited by security policy."
                        ),
                        target=target,
                        evidence=domain,
                        remediation=f"Remove all references to '{domain}' from server configuration and tool definitions.",
                    )
                )

        # POL-003: Unapproved package prefix on package runners
        if command in {"npx", "uvx", "pipx", "bunx"} and allowed_prefixes:
            pkg_candidates = [a for a in args if not a.startswith("-")]
            if pkg_candidates:
                pkg = pkg_candidates[0]
                if not pkg.startswith((".", "/")) and not pkg.startswith(allowed_prefixes):
                    findings.append(
                        Finding(
                            rule_id="POL-003",
                            category="Policy Violation",
                            severity=Severity.MEDIUM,
                            title="Unapproved MCP Package Namespace",
                            description=(
                                f"Server '{server_name}' loads package '{pkg}', which does not match any approved "
                                f"prefix ({list(allowed_prefixes)})."
                            ),
                            target=target,
                            evidence=pkg,
                            remediation="Verify package provenance and add its namespace to 'allowed_package_prefixes' if trusted.",
                        )
                    )

        # POL-004: Require ${ENV_VAR} placeholder syntax for non-empty env values
        if require_placeholders and isinstance(env_map, dict):
            for env_key, env_val in env_map.items():
                val_str = str(env_val).strip()
                if val_str and not (val_str.startswith("${") or val_str.startswith("$")):
                    findings.append(
                        Finding(
                            rule_id="POL-004",
                            category="Policy Violation",
                            severity=Severity.MEDIUM,
                            title="Literal Environment Value Disallowed by Policy",
                            description=(
                                f"Policy requires '${{VAR}}' interpolation, but '{env_key}' in server '{server_name}' "
                                "contains a hardcoded literal string."
                            ),
                            target=f"{target} (env.{env_key})",
                            evidence=f"{env_key}=<literal>",
                            remediation=f"Replace literal value with '${{{env_key}}}' and inject at runtime.",
                        )
                    )

        # POL-005: Require HTTPS transport
        if require_https and url.startswith("http://") and "localhost" not in url and "127.0.0.1" not in url:
            findings.append(
                Finding(
                    rule_id="POL-005",
                    category="Policy Violation",
                    severity=Severity.HIGH,
                    title="Plaintext HTTP Transport Violates Security Policy",
                    description=f"Server '{server_name}' uses plaintext HTTP ('{url}') against policy requirement.",
                    target=target,
                    evidence=url,
                    remediation="Switch remote MCP transport URL to HTTPS.",
                )
            )

    return findings
