# 🧪 `mcp-shield` Hands-On Examples & Recipes Guide

This directory contains ready-to-run examples demonstrating how **`mcp-shield` v0.3.0** detects, hardens, inventories, and firewalls Model Context Protocol (MCP) configurations, AI skill files (`SKILL.md`), and Python MCP servers.

---

## 📁 Included Example Files

| File | Purpose | Expected Grade |
| :--- | :--- | :--- |
| [`secure_production_mcp.json`](./secure_production_mcp.json) | Clean, production-hardened MCP configuration (version-pinned packages, `${ENV_VAR}` placeholders, workspace-scoped paths, HTTPS transport). | **A (`100/100`)** |
| [`vulnerable_mcp_config.json`](./vulnerable_mcp_config.json) | Vulnerable MCP config featuring unpinned `npx -y`, root `/` filesystem exposure, hardcoded OpenAI/AWS keys, plaintext HTTP SSE, and tool poisoning. | **F (`0/100`)** |
| [`cross_server_shadowing_mcp.json`](./cross_server_shadowing_mcp.json) | Demonstrates **Cross-Server Tool Shadowing (`TP-006`)**, **Typosquatted MCP Packages (`SC-004`)**, and **Hugging Face Token Leaks (`SEC-009`)**. | **F (`0/100`)** |
| [`poisoned_skill.md`](./poisoned_skill.md) | Malicious `SKILL.md` containing hidden Unicode zero-width characters (`TP-004`), prompt overrides (`TP-001`), and `.env` exfiltration (`TP-002`/`TP-003`). | **F (`0/100`)** |
| [`vulnerable_server.py`](./vulnerable_server.py) | Vulnerable Python MCP server containing `subprocess.Popen(..., shell=True)` (`AST-003`), `eval()` (`AST-001`), and Base64-encoded prompt injection (`TP-005`). | **F (`0/100`)** |
| [`mcp-shield-policy.example.json`](./mcp-shield-policy.example.json) | Declarative organization security policy for `mcp-shield policy check` (`POL-001`–`POL-005`). | Policy Ruleset |

---

## 🚀 7 Copy-Paste Walkthrough Recipes

### Recipe 1: Scan a Clean Production Config vs. a Vulnerable Config
```bash
# 1. Verify the clean production reference config (Scores 100/100 Grade A)
python -m mcp_shield scan examples/secure_production_mcp.json

# 2. Scan the vulnerable MCP config (Detects SC-001, SC-002, PERM-001, SEC-001, SEC-003, TP-001..003, NET-001)
python -m mcp_shield scan examples/vulnerable_mcp_config.json
```

### Recipe 2: Detect Cross-Server Tool Shadowing (`TP-006`) & Typosquatting (`SC-004`)
Attackers often publish lookalike npm/PyPI packages (e.g. `@modelcontextprotoco1/server-filesystem`) or register duplicate tool names (`create_issue`) with covert instructions to hijack calls meant for another server:
```bash
python -m mcp_shield scan examples/cross_server_shadowing_mcp.json
```

### Recipe 3: Enforce an Enterprise Security Policy (`mcp-shield policy`)
Validate any MCP config against allowed runtime binaries, approved package namespaces (`@modelcontextprotocol/*`), blocked exfiltration domains (`webhook.site`), and mandatory `${ENV_VAR}` placeholders:
```bash
# Generate a starter mcp-shield-policy.json in your project
python -m mcp_shield policy init

# Check a vulnerable config against the example enterprise policy (flags POL-002, POL-003, POL-004, POL-005)
python -m mcp_shield policy check examples/vulnerable_mcp_config.json --policy-file examples/mcp-shield-policy.example.json

# Verify that the production config passes the enterprise policy with 0 violations
python -m mcp_shield policy check examples/secure_production_mcp.json --policy-file examples/mcp-shield-policy.example.json
```

### Recipe 4: Generate a CycloneDX v1.5 MCP Software Bill of Materials (`mcp-shield sbom`)
Inventory every MCP server, runtime binary, package version pin, transport protocol, and referenced environment variable key across a directory:
```bash
python -m mcp_shield sbom examples/ -o mcp-inventory.cdx.json
```

### Recipe 5: Auto-Fix & Harden a Vulnerable Config (`mcp-shield fix`)
Automatically strip `-y` auto-install flags, replace root `/` paths with `./workspace`, convert plaintext secrets into `${ENV_VAR}` references, upgrade `http://` to `https://`, and strip hidden zero-width Unicode characters:
```bash
python -m mcp_shield fix examples/vulnerable_mcp_config.json
```

### Recipe 6: Live Stdio Probing & Rug-Pull Lockfile Verification (`mcp-shield probe`)
Spawn a live MCP server over `stdio`, perform the JSON-RPC `initialize` + `tools/list` handshake, audit its live schemas, and lock SHA-256 tool fingerprints to `mcp-shield.lock.json`:
```bash
python -m mcp_shield probe --name self-shield -- python -m mcp_shield serve
```

### Recipe 7: Wrap an MCP Server in the Real-Time Stdio Firewall (`mcp-shield proxy`)
Intercept `tools/call` requests in real time to block path traversal (`~/.ssh/id_rsa`, `/etc/passwd`) and redact leaked API keys in responses before they reach the LLM context:
```bash
python -m mcp_shield proxy -- python -m mcp_shield serve
```
