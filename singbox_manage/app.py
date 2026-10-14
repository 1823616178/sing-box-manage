"""Compatibility entry point for the singbox-tui console script."""

from .cli import main

__all__ = ["main"]

if __name__ == "__main__":
    raise SystemExit(main())
