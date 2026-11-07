# 🛡️ Security & Pull Request Protection Policy

To protect `MCP-Shield-` from malicious pull requests, supply-chain poisoning, or accidental regressions, the following strict rules are enforced on every Pull Request:

## 1. Automated PR Guardrails (`.github/workflows/ci.yml`)
Every Pull Request automatically runs the **PR Security & Integrity Gate**:
- **Self-Audit (`dogfood` scan):** Runs `python -m mcp_shield scan mcp_shield --fail-on-high` on the package source code itself. Any PR introducing `eval()`, `shell=True`, hardcoded tokens, or prompt injections fails immediately.
- **Zero-Dependency Lock:** Verifies that `pyproject.toml` does not introduce third-party runtime dependencies (`dependencies = []`), preventing upstream PyPI supply-chain attacks.
- **Full Test Matrix:** Runs all unit tests across Python 3.10, 3.11, and 3.12.

## 2. Mandatory Code Owner Approval (`.github/CODEOWNERS`)
- All files in this repository are locked to `@minteeqahmed-png` via `CODEOWNERS`.
- No pull request can modify workflows, scanners, or packaging without maintainer approval.

## 3. CodeRabbit Automated Blocking Reviews (`.coderabbit.yaml`)
- CodeRabbit is configured with `request_changes_workflow: true` to automatically request changes on any PR that weakens security rules, modifies CI gates, or introduces unsafe code patterns.

## Reporting a Vulnerability
If you discover a security issue or bypass in `mcp-shield`, please open a GitHub Security Advisory on [https://github.com/minteeqahmed-png/MCP-Shield-/security/advisories](https://github.com/minteeqahmed-png/MCP-Shield-/security/advisories).
