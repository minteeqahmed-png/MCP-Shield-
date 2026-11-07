## Summary of Changes

<!-- Describe what this PR changes and why -->

## 🛡️ Repository Safety & Security Checklist (Required)

- [ ] **Zero External Dependencies Preserved:** `pyproject.toml` still has `dependencies = []` (no third-party supply-chain packages added).
- [ ] **Self-Scan Clean:** `python -m mcp_shield scan mcp_shield --fail-on-high` passes with `100/100 (Grade: A)`.
- [ ] **Unit Tests Pass:** `python -m unittest discover -s tests -p "test_*.py" -v` passes completely.
- [ ] **No Destructive Changes:** Existing detection rules (`SEC-*`, `TP-*`, `AST-*`, `SC-*`, `PERM-*`, `RP-*`) and CLI flags remain backward-compatible.
