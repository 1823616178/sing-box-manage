"""Allow ``python -m singbox_manage`` execution."""

from singbox_manage.app import main

if __name__ == "__main__":
    raise SystemExit(main())
