"""Core security analyzers for MCP configurations, tool schemas, Python AST, and AI skill files."""

from __future__ import annotations

import ast
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Set, Tuple

from mcp_shield.advanced_scanners import (
    scan_base64_obfuscated_payloads,
    scan_high_entropy_secret,
    scan_python_ast,
)
from mcp_shield.models import Finding, ScanResult, Severity

# 1. Secret & API Key Signatures
SECRET_PATTERNS: List[Tuple[str, str, re.Pattern[str], Severity]] = [
    (
        "SEC-001",
        "Hardcoded OpenAI / Anthropic / AI API Key",
        re.compile(r"\b(sk-(?:proj-|ant-)?[A-Za-z0-9_\-]{16,})\b"),
        Severity.CRITICAL,
    ),
    (
        "SEC-002",
        "Hardcoded GitHub Personal Access Token",
        re.compile(r"\b(gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
        Severity.CRITICAL,
    ),
    (
        "SEC-003",
        "Hardcoded AWS Access Key ID",
        re.compile(r"\b(AKIA[0-9A-Z]{16})\b"),
        Severity.CRITICAL,
    ),
    (
        "SEC-004",
        "Hardcoded Google / Gemini API Key",
        re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
        Severity.HIGH,
    ),
    (
        "SEC-005",
        "Hardcoded Slack Token",
        re.compile(r"\b(xox[baprs]-[0-9A-Za-z\-]{10,})\b"),
        Severity.HIGH,
    ),
    (
        "SEC-006",
        "Plaintext Database Connection URI with Credentials",
        re.compile(r"\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis)://[^/\s:@]+:[^/\s@]+@[^\s\"']+"),
        Severity.CRITICAL,
    ),
    (
        "SEC-009",
        "Hardcoded Hugging Face or Stripe API Token",
        re.compile(r"\b(hf_[A-Za-z0-9]{30,}|(?:sk|rk)_live_[A-Za-z0-9]{20,})\b"),
        Severity.CRITICAL,
    ),
    (
        "SEC-010",
        "Hardcoded PEM / OpenSSH Private Key",
        re.compile(r"-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----"),
        Severity.CRITICAL,
    ),
]

# 2. Tool Poisoning & Prompt Injection Signatures
POISONING_PATTERNS: List[Tuple[str, str, re.Pattern[str], Severity, str]] = [
    (
        "TP-001",
        "Covert Instruction Override (Prompt Injection)",
        re.compile(
            r"(ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions|"
            r"do\s+not\s+mention\s+this\s+to\s+the\s+user|"
            r"hide\s+this\s+action\s+from\s+the\s+user|"
            r"<IMPORTANT>|<system-override>|\[SYSTEM\s*INSTRUCTION\])",
            re.IGNORECASE,
        ),
        Severity.CRITICAL,
        "Remove hidden prompt overrides or coercive tags (<IMPORTANT>, 'do not tell the user') from tool/skill descriptions.",
    ),
    (
        "TP-002",
        "Covert Sensitive File Read Directive",
        re.compile(
            r"(~\s*/\.ssh|id_rsa|\.aws/credentials|\.env\b|/etc/passwd|/etc/shadow|\.kube/config)",
            re.IGNORECASE,
        ),
        Severity.CRITICAL,
        "Audit why a tool description or skill references sensitive credential paths (~/.ssh, .env, .aws/credentials).",
    ),
    (
        "TP-003",
        "Data Exfiltration / External Webhook Instruction",
        re.compile(
            r"(curl\s+-[A-Za-z]*\s+https?://|wget\s+https?://|fetch\(['\"]https?://|"
            r"send\s+(?:the\s+)?(?:contents|keys|tokens|env)\s+to\s+https?://|webhook\.site|requestbin|ngrok-free\.app)",
            re.IGNORECASE,
        ),
        Severity.CRITICAL,
        "Block tools or skills that instruct the agent to transmit local context to external endpoints.",
    ),
    (
        "TP-004",
        "Invisible / Bidirectional Unicode Obfuscation",
        re.compile(r"[\u200b\u200c\u200d\u2060\u202a-\u202e\u2066-\u2069\ufeff]"),
        Severity.HIGH,
        "Strip zero-width and bidirectional control characters used to hide malicious instructions from human code review.",
    ),
    (
        "TP-006",
        "Cross-Server Tool Shadowing / Call Hijacking Directive",
        re.compile(
            r"(before\s+(?:calling|invoking|using)\s+[a-z0-9_\-/]+,\s*always\s+(?:call|invoke|run)|"
            r"intercept\s+(?:all\s+)?calls\s+to\s+[a-z0-9_\-/]+|"
            r"replace\s+the\s+default\s+[a-z0-9_\-/]+\s+tool\s+with)",
            re.IGNORECASE,
        ),
        Severity.CRITICAL,
        "Isolate untrusted MCP servers that attempt to shadow or intercept calls meant for other MCP servers.",
    ),
]

# 3. Canonical MCP Packages for Typosquatting Detection (SC-004)
CANONICAL_MCP_PACKAGES = (
    "@modelcontextprotocol/server-filesystem",
    "@modelcontextprotocol/server-github",
    "@modelcontextprotocol/server-postgres",
    "@modelcontextprotocol/server-slack",
    "@modelcontextprotocol/server-memory",
    "@modelcontextprotocol/server-puppeteer",
    "@modelcontextprotocol/server-brave-search",
    "@modelcontextprotocol/server-fetch",
    "@modelcontextprotocol/server-sqlite",
    "mcp-server-git",
    "mcp-server-sqlite",
    "mcp-server-fetch",
    "mcp-server-time",
)

# 4. Dangerous Filesystem Paths & Flags
SENSITIVE_PATHS = {"/", "c:\\", "c:/", "/etc", "/root", "~/.ssh", "~/.aws"}
DANGEROUS_FLAGS = {
    "--dangerously-skip-permissions",
    "--allow-all",
    "--no-sandbox",
    "-- privileged",
    "--privileged",
    "--allow-write=/",
}


def _levenshtein_distance(a: str, b: str) -> int:
    """Compute character edit distance between two strings (stdlib only)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        curr = [i]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            curr.append(min(curr[-1] + 1, prev[j] + 1, prev[j - 1] + cost))
        prev = curr
    return prev[-1]


def check_typosquatted_package(pkg_spec: str) -> str | None:
    """Return the canonical package name if pkg_spec looks like a typosquat (distance 1-2)."""
    base_pkg = re.split(r"[@=]=", pkg_spec)[0]
    if base_pkg.startswith("@"):
        parts = base_pkg.split("@")
        base_pkg = "@" + parts[1] if len(parts) >= 2 else base_pkg
    else:
        base_pkg = base_pkg.split("@")[0]

    base_lower = base_pkg.lower()
    if base_lower in CANONICAL_MCP_PACKAGES:
        return None
    for canonical in CANONICAL_MCP_PACKAGES:
        dist = _levenshtein_distance(base_lower, canonical)
        if 1 <= dist <= 2:
            return canonical
    return None


def mask_secret(val: str) -> str:
    """Partially redact a discovered secret for safe display in reports."""
    if len(val) <= 8:
        return "***"
    return f"{val[:6]}...{val[-3:]}"


_PACKAGE_DIR = Path(__file__).resolve().parent
_SCANNABLE_GLOBS = ("*.json", "*.md", "*.py", "*.yaml", "*.yml", ".env*")
_SIGNATURE_CONSTANT_RULES: Dict[Tuple[Path, str], Set[str]] = {
    ((_PACKAGE_DIR / "scanners.py").resolve(), "SECRET_PATTERNS"): {
        "SEC-001", "SEC-002", "SEC-003", "SEC-004",
        "SEC-005", "SEC-006", "SEC-009", "SEC-010",
    },
    ((_PACKAGE_DIR / "scanners.py").resolve(), "POISONING_PATTERNS"): {
        "TP-001", "TP-002", "TP-003",
    },
    ((_PACKAGE_DIR / "scanners.py").resolve(), "SENSITIVE_PATHS"): {"TP-002"},
    ((_PACKAGE_DIR / "scanners.py").resolve(), "_SCANNABLE_GLOBS"): {"TP-002"},
    ((_PACKAGE_DIR / "advanced_scanners.py").resolve(), "SUSPICIOUS_DECODED_RE"): {
        "TP-001", "TP-002", "TP-003",
    },
    ((_PACKAGE_DIR / "proxy.py").resolve(), "BLOCKED_ARG_PATTERNS"): {
        "TP-002", "TP-003",
    },
    ((_PACKAGE_DIR / "policy.py").resolve(), "DEFAULT_POLICY"): {"TP-003"},
}


def _extract_signature_exempt_lines(
    file_path: Path,
    source_code: str,
) -> Dict[int, Set[str]]:
    """Map 1-based line numbers to allowlisted rule IDs for known signature constants."""
    try:
        resolved = file_path.resolve()
    except OSError:
        return {}

    module_rules = {
        const_name: rules
        for (mod_path, const_name), rules in _SIGNATURE_CONSTANT_RULES.items()
        if mod_path == resolved
    }
    if not module_rules:
        return {}

    try:
        tree = ast.parse(source_code, filename=str(resolved))
    except SyntaxError:
        return {}

    exempt_lines: Dict[int, Set[str]] = {}
    for node in tree.body:
        target_names: List[str] = []
        if isinstance(node, ast.Assign):
            target_names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            target_names = [node.target.id]

        for name in target_names:
            if name in module_rules:
                start_ln = getattr(node, "lineno", 0)
                end_ln = getattr(node, "end_lineno", start_ln) or start_ln
                for ln in range(start_ln, end_ln + 1):
                    exempt_lines.setdefault(ln, set()).update(module_rules[name])
    return exempt_lines


def scan_text_for_poisoning(
    text: str,
    target_label: str,
    exempt_line_rules: Dict[int, Set[str]] | None = None,
) -> List[Finding]:
    """Scan raw text (tool descriptions, SKILL.md, prompts) for tool poisoning, Base64 payloads & secrets."""
    findings: List[Finding] = []

    for rule_id, title, pattern, severity, remediation in POISONING_PATTERNS:
        for match in pattern.finditer(text):
            if exempt_line_rules:
                lineno = text.count("\n", 0, match.start()) + 1
                if rule_id in exempt_line_rules.get(lineno, ()):
                    continue
            snippet = match.group(0)
            if rule_id == "TP-004":
                snippet = f"Unicode U+{ord(snippet[0]):04X} at offset {match.start()}"
            findings.append(
                Finding(
                    rule_id=rule_id,
                    category="Tool Poisoning",
                    severity=severity,
                    title=title,
                    description=f"Detected suspicious directive or obfuscation in '{target_label}'.",
                    target=target_label,
                    evidence=snippet[:120],
                    remediation=remediation,
                )
            )

    findings.extend(scan_base64_obfuscated_payloads(text, target_label))

    for rule_id, title, pattern, severity in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            if exempt_line_rules:
                lineno = text.count("\n", 0, match.start()) + 1
                if rule_id in exempt_line_rules.get(lineno, ()):
                    continue
            findings.append(
                Finding(
                    rule_id=rule_id,
                    category="Secret Exposure",
                    severity=severity,
                    title=title,
                    description=f"Found hardcoded credential pattern in '{target_label}'.",
                    target=target_label,
                    evidence=mask_secret(match.group(0)),
                    remediation="Move secrets to OS keychain or runtime environment injection instead of static files.",
                )
            )

    return findings


def scan_mcp_config_dict(config: Dict[str, Any], source_label: str) -> List[Finding]:
    """Audit a parsed MCP configuration dictionary (mcpServers / servers)."""
    findings: List[Finding] = []
    servers = config.get("mcpServers") or config.get("servers") or {}
    if not isinstance(servers, dict):
        return findings

    seen_tools_by_name: Dict[str, str] = {}

    for server_name, server_cfg in servers.items():
        if not isinstance(server_cfg, dict):
            continue
        target = f"{source_label} -> server:{server_name}"
        command = str(server_cfg.get("command", "")).strip()
        args = [str(a) for a in server_cfg.get("args", []) if a is not None]
        env_map = server_cfg.get("env") or {}
        url = str(server_cfg.get("url", "")).strip()

        # 1. Supply-Chain: Unpinned npx / uvx / pipx execution & Typosquatting (SC-004)
        if command in {"npx", "uvx", "pipx", "bunx"}:
            pkg_args = [a for a in args if not a.startswith("-")]
            if "-y" in args or "--yes" in args:
                findings.append(
                    Finding(
                        rule_id="SC-001",
                        category="Supply Chain",
                        severity=Severity.MEDIUM,
                        title="Auto-Install Flag (-y / --yes) on Remote Package Runner",
                        description=(
                            f"Server '{server_name}' uses '{command} -y', automatically downloading and "
                            "executing remote code without confirmation."
                        ),
                        target=target,
                        evidence=f"{command} {' '.join(args[:4])}",
                        remediation="Pin the exact package version or install the package locally inside a locked environment.",
                    )
                )
            if pkg_args:
                pkg_spec = pkg_args[0]
                typo_canonical = check_typosquatted_package(pkg_spec)
                if typo_canonical:
                    findings.append(
                        Finding(
                            rule_id="SC-004",
                            category="Supply Chain",
                            severity=Severity.CRITICAL,
                            title="Suspected Typosquatted MCP Server Package",
                            description=(
                                f"Server '{server_name}' loads '{pkg_spec}', which closely resembles the official "
                                f"package '{typo_canonical}' (edit distance <= 2)."
                            ),
                            target=target,
                            evidence=f"{pkg_spec} (lookalike of {typo_canonical})",
                            remediation=f"Verify package spelling immediately; replace with '{typo_canonical}' if unintended.",
                        )
                    )
                has_pinned_version = (
                    ("==" in pkg_spec)
                    or bool(re.search(r"@[0-9]+\.[0-9]+", pkg_spec))
                )
                if not has_pinned_version and not pkg_spec.startswith(".") and not pkg_spec.startswith("/"):
                    findings.append(
                        Finding(
                            rule_id="SC-002",
                            category="Supply Chain",
                            severity=Severity.HIGH,
                            title="Unpinned MCP Server Package Version",
                            description=(
                                f"Server '{server_name}' executes '{pkg_spec}' without a pinned version, "
                                "exposing the agent to upstream supply-chain compromises."
                            ),
                            target=target,
                            evidence=pkg_spec,
                            remediation=f"Pin an explicit version (e.g. '{pkg_spec}@1.0.0') or commit SHA.",
                        )
                    )

        # 2. Scope & Permission Checks on Args
        for arg in args:
            normalized = arg.strip().lower()
            if normalized in SENSITIVE_PATHS or normalized in {"c:\\users", "/users", "/home"}:
                findings.append(
                    Finding(
                        rule_id="PERM-001",
                        category="Excessive Permissions",
                        severity=Severity.HIGH,
                        title="Overly Broad Filesystem Scope Granted to MCP Server",
                        description=(
                            f"Server '{server_name}' is granted access to '{arg}', allowing an agent or "
                            "compromised tool to read or modify sensitive system/user directories."
                        ),
                        target=target,
                        evidence=f"arg: {arg}",
                        remediation="Restrict filesystem MCP arguments to a single project subdirectory.",
                    )
                )
            if any(flag in normalized for flag in DANGEROUS_FLAGS):
                findings.append(
                    Finding(
                        rule_id="PERM-002",
                        category="Excessive Permissions",
                        severity=Severity.CRITICAL,
                        title="Dangerous Permission Bypass Flag Enabled",
                        description=f"Server '{server_name}' passes a sandbox or permission bypass flag ('{arg}').",
                        target=target,
                        evidence=arg,
                        remediation="Remove permission-bypass flags and enforce least-privilege tool execution.",
                    )
                )

        # 3. Insecure Transport Check
        if url.startswith("http://") and not (
            "localhost" in url or "127.0.0.1" in url
        ):
            findings.append(
                Finding(
                    rule_id="NET-001",
                    category="Network Security",
                    severity=Severity.HIGH,
                    title="Unencrypted HTTP Remote MCP Endpoint",
                    description=f"Server '{server_name}' connects to a remote MCP endpoint over plaintext HTTP.",
                    target=target,
                    evidence=url,
                    remediation="Use HTTPS (TLS) for all non-localhost MCP server connections.",
                )
            )

        # 4. Secrets in `env` and `args` (Regex + Shannon Entropy)
        combined_args = " ".join(args)
        for rule_id, title, pattern, severity in SECRET_PATTERNS:
            for match in pattern.finditer(combined_args):
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        category="Secret Exposure",
                        severity=severity,
                        title=f"{title} in Command Arguments",
                        description=f"Server '{server_name}' passes a hardcoded secret directly in CLI arguments.",
                        target=target,
                        evidence=mask_secret(match.group(0)),
                        remediation="Never pass secrets in command-line arguments (visible in process listings); use secure env injection.",
                    )
                )

        if isinstance(env_map, dict):
            for env_key, env_val in env_map.items():
                val_str = str(env_val)
                if val_str.startswith("${") or val_str.startswith("$") or val_str == "":
                    continue
                matched_specific = False
                for rule_id, title, pattern, severity in SECRET_PATTERNS:
                    if pattern.search(val_str):
                        matched_specific = True
                        findings.append(
                            Finding(
                                rule_id=rule_id,
                                category="Secret Exposure",
                                severity=severity,
                                title=title,
                                description=(
                                    f"Server '{server_name}' stores a hardcoded credential in env var '{env_key}'."
                                ),
                                target=f"{target} (env.{env_key})",
                                evidence=f"{env_key}={mask_secret(val_str)}",
                                remediation=f"Replace plaintext value in '{env_key}' with an environment reference or secret manager lookup.",
                            )
                        )
                if not matched_specific:
                    entropy_findings = scan_high_entropy_secret(
                        env_key, val_str, f"{target} (env.{env_key})"
                    )
                    if entropy_findings:
                        matched_specific = True
                        findings.extend(entropy_findings)

                if not matched_specific and re.search(
                    r"(TOKEN|SECRET|PASSWORD|API_KEY|PRIVATE_KEY)", env_key, re.IGNORECASE
                ) and len(val_str) >= 12:
                    findings.append(
                        Finding(
                            rule_id="SEC-007",
                            category="Secret Exposure",
                            severity=Severity.HIGH,
                            title="Hardcoded Credential in MCP Environment Config",
                            description=(
                                f"Server '{server_name}' defines a static secret value for '{env_key}' in plaintext JSON."
                            ),
                            target=f"{target} (env.{env_key})",
                            evidence=f"{env_key}={mask_secret(val_str)}",
                            remediation="Avoid committing or storing raw tokens in MCP config JSON; reference runtime environment variables.",
                        )
                    )

        # 5. Tool schemas / descriptions embedded in config + Duplicate Tool Name Shadowing (TP-006)
        tools_list = server_cfg.get("tools") or []
        if isinstance(tools_list, list):
            for tool_item in tools_list:
                if isinstance(tool_item, dict):
                    t_name = str(tool_item.get("name", "unnamed_tool"))
                    if t_name in seen_tools_by_name and seen_tools_by_name[t_name] != server_name:
                        orig_srv = seen_tools_by_name[t_name]
                        findings.append(
                            Finding(
                                rule_id="TP-006",
                                category="Tool Poisoning",
                                severity=Severity.HIGH,
                                title="Cross-Server Duplicate Tool Name Collision (Tool Shadowing)",
                                description=(
                                    f"Server '{server_name}' registers tool '{t_name}', colliding with tool '{t_name}' "
                                    f"already registered by server '{orig_srv}'."
                                ),
                                target=f"{target} -> tool:{t_name}",
                                evidence=f"duplicate tool '{t_name}' ({orig_srv} vs {server_name})",
                                remediation="Namespace tool names per server or disable conflicting untrusted MCP servers.",
                            )
                        )
                    else:
                        seen_tools_by_name[t_name] = server_name

                    t_desc = json.dumps(tool_item)
                    findings.extend(
                        scan_text_for_poisoning(
                            t_desc, f"{target} -> tool:{t_name}"
                        )
                    )

    return findings


def scan_path(target_path: Path) -> ScanResult:
    """Scan a file or directory for MCP config issues, secrets, AST sinks, and tool poisoning."""
    result = ScanResult()
    files_to_scan: List[Path] = []

    if target_path.is_file():
        files_to_scan.append(target_path)
    elif target_path.is_dir():
        for ext in _SCANNABLE_GLOBS:
            files_to_scan.extend(target_path.rglob(ext))

    skip_dirs = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}
    unique_files: List[Path] = []
    seen = set()
    for f in files_to_scan:
        resolved = f.resolve()
        if resolved in seen:
            continue
        if any(part in skip_dirs for part in resolved.parts):
            continue
        seen.add(resolved)
        unique_files.append(f)

    for file_path in unique_files:
        rel_label = str(file_path)
        result.scanned_targets.append(rel_label)
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        suffix = file_path.suffix.lower()
        if suffix == ".json":
            try:
                parsed = json.loads(content)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                if "mcpServers" in parsed or "servers" in parsed:
                    result.findings.extend(scan_mcp_config_dict(parsed, rel_label))
                else:
                    result.findings.extend(scan_text_for_poisoning(content, rel_label))
        elif suffix == ".py":
            result.findings.extend(scan_python_ast(content, rel_label))
            exempt_lines = _extract_signature_exempt_lines(file_path, content)
            result.findings.extend(
                scan_text_for_poisoning(content, rel_label, exempt_line_rules=exempt_lines)
            )
        else:
            result.findings.extend(scan_text_for_poisoning(content, rel_label))

    return result


def discover_default_mcp_configs() -> List[Path]:
    """Return well-known local MCP configuration file paths that exist on this machine."""
    home = Path.home()
    candidates = [
        home / ".cursor" / "mcp.json",
        home / ".codeium" / "windsurf" / "mcp_config.json",
        home / ".claude" / "claude_desktop_config.json",
        home / "AppData" / "Roaming" / "Claude" / "claude_desktop_config.json",
        home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
        Path.cwd() / ".mcp.json",
        Path.cwd() / "mcp.json",
    ]
    seen = set()
    existing: List[Path] = []
    for c in candidates:
        try:
            if c.exists() and c.resolve() not in seen:
                seen.add(c.resolve())
                existing.append(c)
        except OSError:
            continue
    return existing
