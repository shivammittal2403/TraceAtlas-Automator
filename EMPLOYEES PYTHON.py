#!/usr/bin/env python3
"""Launch dedicated TraceAtlas employees from source or an installed package."""
from pathlib import Path
import sys


def main():
    if sys.version_info < (3, 10):
        sys.stderr.write('{"status":"ERROR","error":"Python 3.10 or newer is required"}\n')
        return 2
    root = Path(__file__).resolve().parent / "src"
    if (root / "traceatlas" / "workforce" / "discipline_cli.py").is_file():
        sys.path.insert(0, str(root))
    try:
        from traceatlas.workforce.discipline_cli import main as cli_main
    except ImportError:
        sys.stderr.write('{"status":"ERROR","error":"Keep this launcher beside src or install with python -m pip install ."}\n')
        return 2
    return cli_main()


if __name__ == "__main__":
    raise SystemExit(main())
