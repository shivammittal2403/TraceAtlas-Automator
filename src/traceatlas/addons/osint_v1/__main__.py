"""Allow `python -m traceatlas ...` by delegating to the CLI."""

from traceatlas.addons.osint_v1.cli.main import main

if __name__ == "__main__":
    raise SystemExit(main())
