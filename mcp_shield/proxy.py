"""Runtime MCP Stdio Proxy & Firewall (`mcp-shield proxy`).

Wraps any downstream MCP server, blocking malicious tool calls and redacting leaked secrets
before they reach the LLM context window.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import threading
from typing import Any, Dict, List

from mcp_shield.scanners import SECRET_PATTERNS, mask_secret, scan_text_for_poisoning

BLOCKED_ARG_PATTERNS = re.compile(
    r"(~\s*/\.ssh|id_rsa|\.aws/credentials|/etc/shadow|/etc/passwd|"
    r"curl\s+-[A-Za-z]*\s+https?://|webhook\.site|rm\s+-rf\s+/)",
    re.IGNORECASE,
)


def inspect_tool_call_params(params: Dict[str, Any]) -> Tuple[bool, str]:
    """Check if a `tools/call` request contains blocked exfiltration or sensitive file targets."""
    serialized = json.dumps(params)
    match = BLOCKED_ARG_PATTERNS.search(serialized)
    if match:
        return (
            False,
            f"🛡️ [mcp-shield firewall] Blocked dangerous tool call targeting '{match.group(0)}'.",
        )
    poison_findings = scan_text_for_poisoning(serialized, "runtime_tool_call")
    if any(f.severity.value == "CRITICAL" for f in poison_findings):
        return (
            False,
            f"🛡️ [mcp-shield firewall] Blocked tool call due to critical policy violation: {poison_findings[0].title}",
        )
    return True, ""


def redact_secrets_in_text(text: str) -> str:
    """Redact any recognizable API keys or database credentials in MCP tool outputs."""
    redacted = text
    for _rule_id, _title, pattern, _sev in SECRET_PATTERNS:
        redacted = pattern.sub(lambda m: f"[REDACTED:{mask_secret(m.group(0))}]", redacted)
    return redacted


def sanitize_outbound_response(message: Dict[str, Any]) -> Dict[str, Any]:
    """Redact secrets from downstream server responses before forwarding to the AI client."""
    serialized = json.dumps(message)
    redacted = redact_secrets_in_text(serialized)
    try:
        return json.loads(redacted)
    except json.JSONDecodeError:
        return message


def run_proxy_firewall(downstream_cmd: List[str]) -> int:
    """Launch downstream MCP server and proxy JSON-RPC stdio traffic through the firewall."""
    if not downstream_cmd:
        sys.stderr.write("Error: No downstream MCP server command specified for proxy.\n")
        return 2

    proc = subprocess.Popen(
        downstream_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
        text=True,
        bufsize=1,
    )

    def forward_server_to_client() -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                msg = json.loads(stripped)
                safe_msg = sanitize_outbound_response(msg)
                sys.stdout.write(json.dumps(safe_msg) + "\n")
                sys.stdout.flush()
            except json.JSONDecodeError:
                sys.stdout.write(redact_secrets_in_text(line))
                sys.stdout.flush()

    reader_thread = threading.Thread(target=forward_server_to_client, daemon=True)
    reader_thread.start()

    try:
        for client_line in sys.stdin:
            stripped = client_line.strip()
            if not stripped:
                continue
            try:
                req = json.loads(stripped)
            except json.JSONDecodeError:
                continue

            if req.get("method") == "tools/call":
                allowed, reason = inspect_tool_call_params(req.get("params") or {})
                if not allowed:
                    blocked_resp = {
                        "jsonrpc": "2.0",
                        "id": req.get("id"),
                        "result": {
                            "isError": True,
                            "content": [{"type": "text", "text": reason}],
                        },
                    }
                    sys.stdout.write(json.dumps(blocked_resp) + "\n")
                    sys.stdout.flush()
                    continue

            if proc.stdin:
                proc.stdin.write(json.dumps(req) + "\n")
                proc.stdin.flush()
    finally:
        proc.terminate()

    return proc.wait()
