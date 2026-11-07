# Contributing to 🛡️ mcp-shield

Thank you for helping secure the AI Agent and Model Context Protocol (MCP) ecosystem!

## How Our AI-Assisted PR Workflow Works
Every Pull Request opened on this repository is automatically reviewed by two systems before `@minteeqahmed-png` merges it:
1. **CodeRabbit AI Reviewer (`.coderabbit.yaml`):** Reviews your diff line-by-line for Python security, regex safety (ReDoS), and code quality.
2. **mcp-shield Maintainer Bot (`.github/workflows/pr-maintainer.yml`):** Automatically runs our zero-dependency supply-chain lock, AST self-audit, and unit tests, then posts a pass/fail scorecard comment directly on your PR.

## Quick Steps to Contribute
1. Fork the repository and create a feature branch (`git checkout -b feat/new-rule`).
2. Add your detection rule or feature inside `mcp_shield/` (using **only** the Python 3.10+ standard library).
3. Add a corresponding unit test in `tests/test_scanners.py` and verify locally:
   ```bash
   python -m unittest discover -s tests -p "test_*.py" -v
   ```
4. Open a Pull Request—**CodeRabbit** and the **Maintainer Bot** will review it automatically!
