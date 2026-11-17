# Changelog

## [0.3.0] - 2026-11-18
### Added
- **Declarative Security Policy Engine (`mcp-shield policy init` & `mcp-shield policy check`):** Validate MCP configs against organization allowlists, approved package prefixes, blocked exfiltration domains, and mandatory `${ENV_VAR}` placeholders (`POL-001` through `POL-005`).
- **CycloneDX v1.5 SBOM & MCP Inventory Generator (`mcp-shield sbom`):** Generate standard CycloneDX v1.5 JSON Software Bills of Materials and terminal inventory tables across configured MCP servers.
- **Cross-Server Tool Shadowing Detection (`TP-006`):** Detect duplicate tool name collisions across servers and coercive prompt instructions attempting to intercept calls to other MCP servers.
- **Typosquatted MCP Package Detector (`SC-004`):** Built-in Levenshtein edit-distance analyzer that flags lookalike packages targeting official `@modelcontextprotocol/*` and `mcp-server-*` packages.
- **Expanded Credential Signatures (`SEC-009` & `SEC-010`):** Detect hardcoded Hugging Face (`hf_...`), Stripe live (`sk_live_...`, `rk_live_...`), and PEM/OpenSSH private keys.
- **New Bundled Examples & Recipes Guide (`examples/`):** Added `examples/secure_production_mcp.json` (100/100 Grade A reference), `examples/cross_server_shadowing_mcp.json`, `examples/mcp-shield-policy.example.json`, and `examples/EXAMPLES_GUIDE.md`.

## [0.1.0] - 2026-11-07
### Added
- Core MCP configuration security scanner (`SEC-001..008`, `SC-001..002`, `PERM-001..002`, `NET-001`).
- Tool poisoning, covert prompt injection, Unicode obfuscation, and Base64 payload detectors (`TP-001..005`).
- Python AST dangerous execution sink analyzer (`AST-001..003`).
- Live stdio MCP server prober and SHA-256 tool schema lockfile (`RP-001`).
- Runtime stdio MCP firewall proxy (`mcp-shield proxy`) and auto-fixer (`mcp-shield fix`).
- Terminal scorecard, dark-mode HTML dashboard, JSON, and SARIF v2.1.0 exporters.
