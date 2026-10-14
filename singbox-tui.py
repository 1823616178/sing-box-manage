#!/usr/bin/env python3
"""Backward-compatible launcher for existing installations."""

from singbox_manage.app import main

if __name__ == "__main__":
    raise SystemExit(main())
