"""Allow running mcp-shield via `python -m mcp_shield`."""

from mcp_shield.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
