"""Advanced analyzers: Shannon entropy, Base64 payload decoding, and Python AST inspection."""

from __future__ import annotations

import ast
import base64
import math
import re
from pathlib import Path
from typing import List

from mcp_shield.models import Finding, Severity


BASE64_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9+/])(?:[A-Za-z0-9+/]{24,}={0,2})(?![A-Za-z0-9+/=])")
SUSPICIOUS_DECODED_RE = re.compile(
    r"(ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions|"
    r"curl\s+|wget\s+|webhook\.site|/\.ssh|id_rsa|\.aws/credentials|"
    r"do\s+not\s+mention|system\s+instruction|/etc/passwd)",
    re.IGNORECASE,
)

DANGEROUS_AST_CALLS = {
    "eval": ("AST-001", Severity.CRITICAL, "Dynamic Code Execution via eval()"),
    "exec": ("AST-001", Severity.CRITICAL, "Dynamic Code Execution via exec()"),
    "os.system": ("AST-002", Severity.HIGH, "Unchecked Shell Execution via os.system()"),
    "os.popen": ("AST-002", Severity.HIGH, "Unchecked Shell Execution via os.popen()"),
}


def calculate_shannon_entropy(data: str) -> float:
    """Calculate the Shannon entropy (bits per character) of a string."""
    if not data:
        return 0.0
    length = len(data)
    frequencies = {}
    for ch in data:
        frequencies[ch] = frequencies.get(ch, 0) + 1
    return -sum((count / length) * math.log2(count / length) for count in frequencies.values())


def scan_high_entropy_secret(key_name: str, val_str: str, target_label: str) -> List[Finding]:
    """Detect high-entropy secret strings in environment variables or config fields."""
    findings: List[Finding] = []
    # Skip placeholders, paths, URLs, and short values
    if (
        len(val_str) < 20
        or " " in val_str
        or val_str.startswith(("${", "$", "http://", "https://", "/", "C:\\", "."))
    ):
        return findings

    entropy = calculate_shannon_entropy(val_str)
    has_mixed_charset = (
        any(c.islower() for c in val_str)
        and any(c.isupper() for c in val_str)
        and any(c.isdigit() for c in val_str)
    )
    if entropy >= 4.15 and has_mixed_charset:
        masked = f"{val_str[:5]}...{val_str[-3:]}"
        findings.append(
            Finding(
                rule_id="SEC-008",
                category="Secret Exposure (Entropy)",
                severity=Severity.HIGH,
                title=f"High-Entropy Secret Detected ({entropy:.2f} bits/char)",
                description=(
                    f"Field '{key_name}' contains a high-entropy token ({entropy:.2f} bits/char) "
                    "indicative of an unencrypted API key or cryptographic secret."
                ),
                target=target_label,
                evidence=f"{key_name}={masked}",
                remediation=f"Replace hardcoded secret in '{key_name}' with '${{{key_name}}}' environment variable lookup.",
            )
        )
    return findings


def scan_base64_obfuscated_payloads(text: str, target_label: str) -> List[Finding]:
    """Find Base64 blobs in descriptions/skills, decode them, and check for hidden prompt injections."""
    findings: List[Finding] = []
    for match in BASE64_CANDIDATE_RE.finditer(text):
        b64_str = match.group(0)
        if len(b64_str) % 4 != 0:
            continue
        try:
            decoded_bytes = base64.b64decode(b64_str, validate=True)
            decoded_text = decoded_bytes.decode("utf-8")
        except Exception:
            continue

        # Check if decoded text is printable ASCII/UTF-8 and contains suspicious directives
        if not all(c.isprintable() or c in "\r\n\t" for c in decoded_text):
            continue

        if SUSPICIOUS_DECODED_RE.search(decoded_text):
            findings.append(
                Finding(
                    rule_id="TP-005",
                    category="Tool Poisoning (Obfuscated)",
                    severity=Severity.CRITICAL,
                    title="Base64-Encoded Prompt Injection / Exfiltration Payload",
                    description=(
                        f"Decoded a Base64 payload in '{target_label}' containing covert agent instructions."
                    ),
                    target=target_label,
                    evidence=f"b64({b64_str[:20]}...) -> '{decoded_text[:80]}'",
                    remediation="Remove Base64-encoded instructions and audit the tool/skill author immediately.",
                )
            )
    return findings


def scan_python_ast(source_code: str, target_label: str) -> List[Finding]:
    """Parse Python MCP server code via AST to detect dangerous execution sinks."""
    findings: List[Finding] = []
    try:
        tree = ast.parse(source_code, filename=target_label)
    except SyntaxError:
        return findings

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func_name = _get_call_name(node.func)
            lineno = getattr(node, "lineno", "?")
            loc_target = f"{target_label}:{lineno}"

            if func_name in DANGEROUS_AST_CALLS:
                rule_id, severity, title = DANGEROUS_AST_CALLS[func_name]
                findings.append(
                    Finding(
                        rule_id=rule_id,
                        category="Dangerous Code Sink (AST)",
                        severity=severity,
                        title=title,
                        description=(
                            f"Python MCP script invokes '{func_name}()' at line {lineno}, "
                            "which can lead to arbitrary command execution if fed untrusted tool arguments."
                        ),
                        target=loc_target,
                        evidence=f"{func_name}(...) at line {lineno}",
                        remediation="Avoid eval/exec/os.system in MCP servers; use parameterized APIs or strict allowlists.",
                    )
                )

            elif func_name in {
                "subprocess.Popen",
                "subprocess.run",
                "subprocess.call",
                "subprocess.check_output",
            }:
                for kw in node.keywords:
                    if (
                        kw.arg == "shell"
                        and isinstance(kw.value, ast.Constant)
                        and kw.value.value is True
                    ):
                        findings.append(
                            Finding(
                                rule_id="AST-003",
                                category="Dangerous Code Sink (AST)",
                                severity=Severity.CRITICAL,
                                title="Subprocess Invoked with shell=True in MCP Server",
                                description=(
                                    f"Call to '{func_name}(..., shell=True)' at line {lineno} enables "
                                    "shell command injection via LLM tool arguments."
                                ),
                                target=loc_target,
                                evidence=f"{func_name}(..., shell=True) at line {lineno}",
                                remediation="Pass command arguments as a list with shell=False and validate inputs.",
                            )
                        )

    return findings


def _get_call_name(func_node: ast.AST) -> str:
    if isinstance(func_node, ast.Name):
        return func_node.id
    if isinstance(func_node, ast.Attribute):
        parent = _get_call_name(func_node.value)
        return f"{parent}.{func_node.attr}" if parent else func_node.attr
    return ""
