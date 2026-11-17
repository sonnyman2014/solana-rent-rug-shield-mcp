"""Module entry point allowing `python3 -m solana_rug_shield --mcp-stdio`."""

from __future__ import annotations

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
