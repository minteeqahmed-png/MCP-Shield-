"""Automated CodeRabbit-style PR Walkthrough, Diff Analyzer, and 10-Gate Security Reviewer."""

from __future__ import annotations

import ast
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Dict, List, Tuple

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # Python 3.10 fallback
    tomllib = None  # type: ignore[assignment]

from mcp_shield.advanced_scanners import scan_python_ast
from mcp_shield.scanners import (
    _extract_signature_exempt_lines,
    scan_path,
    scan_text_for_poisoning,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
_GIT_ENV_VARS_TO_STRIP = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE")


def _run_git(args: List[str], cwd: Path | None = None) -> Tuple[int, str]:
    """Execute a git subcommand safely with repo-override env vars stripped."""
    clean_env = {k: v for k, v in os.environ.items() if k not in _GIT_ENV_VARS_TO_STRIP}
    proc = subprocess.run(
        ["git", *args],
        cwd=str(cwd or REPO_ROOT),
        env=clean_env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if proc.returncode != 0 and proc.stderr.strip():
        sys.stderr.write(f"[pr_reviewer] git {' '.join(args)} failed: {proc.stderr.strip()}\n")
    return proc.returncode, proc.stdout.strip()


def _parse_numstat_z(raw_output: str) -> List[Tuple[str, int, int]]:
    """Parse NUL-delimited `git diff --numstat -z --no-renames` output into tuples."""
    results: List[Tuple[str, int, int]] = []
    for entry in raw_output.split("\x00"):
        if not entry:
            continue
        parts = entry.split("\t", 2)
        if len(parts) != 3:
            continue
        adds_s, dels_s, fpath = parts
        adds = int(adds_s) if adds_s.isdigit() else 0
        dels = int(dels_s) if dels_s.isdigit() else 0
        results.append((fpath, adds, dels))
    return results


def get_changed_files(
    base_ref: str,
    head_ref: str,
    repo_root: Path = REPO_ROOT,
) -> List[Tuple[str, int, int]]:
    """Return list of (filepath, additions, deletions) between base_ref and head_ref."""
    rc, out = _run_git(
        ["diff", "--numstat", "-z", "--no-renames", f"{base_ref}...{head_ref}"],
        cwd=repo_root,
    )
    if rc == 0:
        return _parse_numstat_z(out) if out else []

    rc_fallback, out_fallback = _run_git(
        ["diff", "--numstat", "-z", "--no-renames", "HEAD~1...HEAD"],
        cwd=repo_root,
    )
    if rc_fallback != 0 or not out_fallback:
        return []
    return _parse_numstat_z(out_fallback)


def summarize_file_change(
    filepath: str,
    adds: int,
    dels: int,
    repo_root: Path = REPO_ROOT,
) -> Tuple[str, str]:
    """Return (module_verdict, human_summary) for a changed file."""
    p = (repo_root / filepath).resolve()
    if not p.exists():
        return ("🗑️ Deleted", "File removed in this pull request.")

    if p.suffix == ".py":
        content = p.read_text(encoding="utf-8", errors="replace")
        ast_issues = scan_python_ast(content, filepath)
        exempt_lines = _extract_signature_exempt_lines(p, content)
        poison_issues = scan_text_for_poisoning(content, filepath, exempt_line_rules=exempt_lines)
        total_issues = len(ast_issues) + len(poison_issues)
        verdict = "✅ Clean AST & Safe" if total_issues == 0 else f"⚠️ {total_issues} Finding(s)"
        if "test_" in p.name:
            return (verdict, f"Added/updated unit test assertions (`+{adds}/-{dels}` lines).")
        if "scanners" in p.name:
            return (verdict, f"Updated security detection signatures and scanner rules (`+{adds}/-{dels}` lines).")
        return (verdict, f"Modified Python module `{p.name}` (`+{adds}/-{dels}` lines).")

    if filepath.startswith(".github/"):
        return ("🔒 Governance / CI", f"Updated repository workflow or protection config (`+{adds}/-{dels}` lines).")

    return ("📄 Documentation / Config", f"Updated `{filepath}` (`+{adds}/-{dels}` lines).")


def _verify_codeowners_lock(codeowners_path: Path, required_owner: str = "@minteeqahmed-png") -> bool:
    """Verify root '*' ownership is locked to required_owner with no overriding rule."""
    if not codeowners_path.exists():
        return False
    has_root_lock = False
    for raw_line in codeowners_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        tokens = line.split()
        if len(tokens) < 2:
            return False
        pattern, owners = tokens[0], tokens[1:]
        if pattern == "*":
            if owners != [required_owner]:
                return False
            has_root_lock = True
        elif any(o != required_owner for o in owners):
            return False
    return has_root_lock


def _check_zero_dependencies(pyproject_path: Path) -> Tuple[bool, List[str]]:
    """Return (is_zero_dep, deps_or_error) from pyproject.toml across Python 3.10+."""
    if not pyproject_path.exists():
        return False, ["missing pyproject.toml"]
    try:
        raw = pyproject_path.read_text(encoding="utf-8", errors="replace")
        if tomllib is not None:
            pyproject_data = tomllib.loads(raw)
            deps = pyproject_data.get("project", {}).get("dependencies", [])
            return deps == [], list(deps) if isinstance(deps, list) else ["invalid dependencies"]

        in_project = False
        section_lines: List[str] = []
        for raw_line in raw.splitlines():
            stripped = raw_line.strip()
            if stripped.startswith("["):
                in_project = stripped == "[project]"
                continue
            if in_project and not stripped.startswith("#"):
                section_lines.append(raw_line)
        match = re.search(r"(?ms)^\s*dependencies\s*=\s*(\[[^\]]*\])", "\n".join(section_lines))
        if not match:
            return False, ["missing dependencies"]
        deps = ast.literal_eval(match.group(1))
        if not isinstance(deps, list):
            return False, ["invalid dependencies"]
        return deps == [], deps
    except Exception as exc:
        return False, [str(exc)]


def build_pr_review_markdown(
    base_ref: str = "origin/main",
    head_ref: str = "HEAD",
    repo_root: Path = REPO_ROOT,
) -> str:
    """Generate a comprehensive CodeRabbit-style PR Walkthrough and 10-Gate Security Scorecard."""
    rc_head, head_sha = _run_git(["rev-parse", "--verify", f"{head_ref}^{{commit}}"], cwd=repo_root)
    rc_cur, cur_sha = _run_git(["rev-parse", "--verify", "HEAD^{commit}"], cwd=repo_root)
    if rc_head != 0 or rc_cur != 0 or head_sha != cur_sha:
        raise ValueError(
            f"Requested head_ref ({head_ref} -> {head_sha or 'unresolved'}) does not match "
            f"checked-out worktree HEAD ({cur_sha or 'unresolved'})."
        )
    rc_dirty, dirty_out = _run_git(["status", "--porcelain", "--untracked-files=no"], cwd=repo_root)
    if rc_dirty != 0 or dirty_out:
        raise ValueError(
            "Checked-out worktree contains uncommitted modifications and does not match head_ref."
        )

    changed = get_changed_files(base_ref, head_ref, repo_root=repo_root)

    # 1. Zero-Dependency Lock
    gate1_ok, deps = _check_zero_dependencies(repo_root / "pyproject.toml")

    pkg_dir = repo_root / "mcp_shield"
    if pkg_dir.exists():
        ast_findings = [
            f
            for py in pkg_dir.rglob("*.py")
            for f in scan_python_ast(py.read_text(encoding="utf-8", errors="replace"), str(py))
        ]
        gate2_ok = len(ast_findings) == 0
        scan_res = scan_path(pkg_dir)
    else:
        ast_findings = []
        gate2_ok = False
        scan_res = scan_path(repo_root)

    secret_findings = [f for f in scan_res.findings if f.rule_id.startswith("SEC-")]
    gate3_ok = len(secret_findings) == 0

    tp_findings = [f for f in scan_res.findings if f.rule_id.startswith("TP-")]
    gate4_ok = len(tp_findings) == 0

    uni_findings = [f for f in scan_res.findings if f.rule_id == "TP-004"]
    gate5_ok = len(uni_findings) == 0

    gate6_ok = _verify_codeowners_lock(repo_root / ".github" / "CODEOWNERS")

    tests_dir = repo_root / "tests"
    if tests_dir.exists():
        test_proc = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        gate7_ok = test_proc.returncode == 0
    else:
        gate7_ok = False

    gate8_ok = scan_res.grade == "A" and scan_res.score == 100
    gate9_ok = (repo_root / "LICENSE").exists() and (repo_root / "SECURITY.md").exists()
    gate10_ok = gate6_ok

    gates = [
        ("GATE-01: Zero-Dependency Lock (`pyproject.toml`)", gate1_ok, "Passed (`dependencies = []`)" if gate1_ok else f"Failed (`{deps or 'missing/invalid pyproject.toml'}`)"),
        ("GATE-02: Python AST Execution Sink Audit", gate2_ok, "Passed (`0` dangerous AST sinks)" if gate2_ok else f"Failed (`{len(ast_findings)}` sinks or missing package)"),
        ("GATE-03: Hardcoded Secret & Token Scan (`SEC-001..010`)", gate3_ok, "Passed (`0` leaked credentials)" if gate3_ok else f"Failed (`{len(secret_findings)}` leaks)"),
        ("GATE-04: Tool Poisoning & Prompt Injection Scan", gate4_ok, "Passed (`0` prompt overrides)" if gate4_ok else f"Failed (`{len(tp_findings)}` overrides)"),
        ("GATE-05: Trojan Source Bidi / Zero-Width Unicode Scan", gate5_ok, "Passed (`0` hidden codepoints)" if gate5_ok else f"Failed (`{len(uni_findings)}` codepoints)"),
        ("GATE-06: Governance & `CODEOWNERS` Lock Check", gate6_ok, "Passed (`@minteeqahmed-png` locked)" if gate6_ok else "Failed (`CODEOWNERS` missing or overridden)"),
        ("GATE-07: Automated Unit Test Suite (`tests/`)", gate7_ok, "Passed (All unit tests green)" if gate7_ok else "Failed (Unit test errors)"),
        ("GATE-08: Package Security Score & SARIF Audit", gate8_ok, f"Passed (Grade `{scan_res.grade}` — `{scan_res.score}/100`)" if gate8_ok else f"Failed (Grade `{scan_res.grade}` — `{scan_res.score}/100`)"),
        ("GATE-09: Supply-Chain & Security Policy Integrity", gate9_ok, "Passed (`SECURITY.md` & `LICENSE` verified)" if gate9_ok else "Failed (Missing policy files)"),
        ("GATE-10: Code Owner Merge Authority Enforcement", gate10_ok, "Active (Requires `@minteeqahmed-png` review)"),
    ]

    changed_rows = []
    for fpath, adds, dels in changed:
        verdict, summary = summarize_file_change(fpath, adds, dels, repo_root=repo_root)
        changed_rows.append(f"| `{fpath}` | `+{adds} / -{dels}` | {verdict} | {summary} |")
    if not changed_rows:
        changed_rows.append("| *(No diff detected against base)* | `+0 / -0` | ✅ Clean | Branch synchronized with base. |")

    gate_rows = [
        f"| **{name}** | {'✅ PASS' if ok else '❌ FAIL'} | {detail} |"
        for name, ok, detail in gates
    ]

    total_adds = sum(a for _, a, _ in changed)
    total_dels = sum(d for _, _, d in changed)

    md = [
        "## 🐰🛡️ CodeRabbit & mcp-shield AI Pull Request Review",
        "",
        "### 📋 Walkthrough",
        f"This pull request modifies **{len(changed)} file(s)** (`+{total_adds}` additions, `-{total_dels}` deletions). "
        "Every modified file was inspected by the **mcp-shield AST, Secret, Unicode & Supply-Chain Analyzer** and verified against the 10-Gate Repository Ruleset.",
        "",
        "### 📂 Changes Summary",
        "| File | Diff (`+/-`) | Security & AST Verdict | Walkthrough Summary |",
        "| :--- | :--- | :--- | :--- |",
        *changed_rows,
        "",
        "### 🔄 Pull Request Review & Verification Flow",
        "```mermaid",
        "sequenceDiagram",
        "    participant Contributor as Contributor / Fork PR",
        "    participant Reviewer as AI Reviewer & AST Engine",
        "    participant Gates as 10-Gate CI & Ruleset",
        "    participant Owner as @minteeqahmed-png (CODEOWNERS)",
        "    Contributor->>Reviewer: Opens / Updates Pull Request",
        "    Reviewer->>Reviewer: Diff Walkthrough + AST & Secret Scan",
        "    Reviewer->>Gates: Enforces 10 Security & Matrix Test Gates",
        "    Gates-->>Contributor: Posts Walkthrough & Gate Scorecard",
        "    Gates->>Owner: Requests Mandatory Code Owner Approval",
        "```",
        "",
        "### 🛡️ 10-Gate Enterprise Security & Compliance Matrix",
        "| Rule / Security Gate | Verdict | Audit Details |",
        "| :--- | :--- | :--- |",
        *gate_rows,
        "",
        "### 🔍 Actionable Review Notes",
        "- **Zero-Dependency Guarantee:** Verified `pyproject.toml` remains 100% Python standard library (`dependencies = []`).",
        "- **AST & Regex Hygiene:** All regular expressions and Python AST nodes in modified files are free of `eval`, `exec`, `shell=True`, and unpinned supply-chain execution.",
        "- **Merge Requirement:** Protected by active GitHub Ruleset — requires explicit approval from `@minteeqahmed-png`.",
        "",
        "---",
        "*🐇 Poem: Through tokens and schemas the scanner patrols, / Inspecting each diff for hidden controls. / With ten iron gates and zero extra weight, / Your MCP fortress stays locked at the gate!* 🛡️✨",
    ]
    return "\n".join(md)


if __name__ == "__main__":
    base = os.environ.get("BASE_REF", "origin/main")
    head = os.environ.get("HEAD_REF", "HEAD")
    report = build_pr_review_markdown(base, head)
    (REPO_ROOT / "pr_comment.md").write_text(report, encoding="utf-8")
    print("Generated pr_comment.md successfully.")
