"""Compatibility entry point for running the project without installation."""

from safecode_auditor.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
