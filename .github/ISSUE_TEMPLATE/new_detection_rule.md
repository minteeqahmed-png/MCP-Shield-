---
name: "🛡️ New Security Detection Rule"
about: "Propose a new MCP vulnerability, tool poisoning signature, or AST check (great for contributors & AI agents)"
title: "[Rule]: Detect <vulnerability type>"
labels: ["enhancement", "security-rule", "good first issue"]
---

## Vulnerability Description
Describe the MCP configuration risk, prompt injection pattern, or secret format to detect.

## Proposed Rule ID & Severity
- **Rule ID:** (e.g., `TP-006`, `SEC-009`, `SC-003`)
- **Severity:** `CRITICAL` / `HIGH` / `MEDIUM` / `LOW`

## Example Vulnerable Payload
```json
{
  "mcpServers": {}
}
```

## Acceptance Criteria for PR
- [ ] Implemented in `mcp_shield/scanners.py` or `mcp_shield/advanced_scanners.py`
- [ ] Unit test added in `tests/test_scanners.py`
- [ ] Zero external dependencies (`dependencies = []`)
