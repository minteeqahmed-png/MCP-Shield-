"""Zero-dependency Model Context Protocol (MCP) stdio JSON-RPC server for mcp-shield."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict

from mcp_shield import __version__
from mcp_shield.scanners import (
    discover_default_mcp_configs,
    scan_path,
    scan_text_for_poisoning,
)


TOOLS_SCHEMA = [
    {
        "name": "scan_mcp_path",
        "description": (
            "Scan a file or directory (such as mcp.json, claude_desktop_config.json, or a skills folder) "
            "for hardcoded secrets, tool poisoning prompt injections, and supply-chain vulnerabilities."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path to the MCP config file or directory to audit.",
                }
            },
            "required": ["path"],
        },
    },
    {
        "name": "audit_text_for_poisoning",
        "description": (
            "Inspect a tool description, skill markdown, or system prompt snippet for covert "
            "prompt injections, exfiltration webhooks, and invisible Unicode characters."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "Raw text or tool schema description to inspect.",
                },
                "label": {
                    "type": "string",
                    "description": "Optional identifier for the text being audited.",
                },
            },
            "required": ["text"],
        },
    },
    {
        "name": "discover_local_mcp_configs",
        "description": "Discover and audit standard MCP configuration files present on the local machine.",
        "inputSchema": {
            "type": "object",
            "properties": {},
        },
    },
]


def handle_rpc_request(request: Dict[str, Any]) -> Dict[str, Any] | None:
    """Process a single JSON-RPC 2.0 request from an MCP client."""
    method = request.get("method", "")
    req_id = request.get("id")
    params = request.get("params") or {}

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {
                    "name": "mcp-shield",
                    "version": __version__,
                },
            },
        }

    if method.startswith("notifications/"):
        return None

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"tools": TOOLS_SCHEMA},
        }

    if method == "tools/call":
        tool_name = params.get("name")
        args = params.get("arguments") or {}

        if tool_name == "scan_mcp_path":
            target = Path(str(args.get("path", ".")))
            if not target.exists():
                payload = {"error": f"Path not found: {target}"}
            else:
                payload = scan_path(target).to_dict()
        elif tool_name == "audit_text_for_poisoning":
            text = str(args.get("text", ""))
            label = str(args.get("label", "inline_snippet"))
            findings = scan_text_for_poisoning(text, label)
            payload = {
                "label": label,
                "finding_count": len(findings),
                "findings": [f.to_dict() for f in findings],
            }
        elif tool_name == "discover_local_mcp_configs":
            discovered = discover_default_mcp_configs()
            combined = [str(p) for p in discovered]
            payload = {"discovered_configs": combined}
        else:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"},
            }

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(payload, indent=2),
                    }
                ]
            },
        }

    if req_id is not None:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }
    return None


def run_stdio_server() -> None:
    """Run the MCP server over standard input/output."""
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        resp = handle_rpc_request(req)
        if resp is not None:
            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
