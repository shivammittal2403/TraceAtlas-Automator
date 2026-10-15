#!/usr/bin/env python3
"""Launch TraceAtlas OSINT from this checkout or an installed package."""
from pathlib import Path
import sys


def main():
    if sys.version_info < (3, 10):
        sys.stderr.write('{"status":"ERROR","error":"Python 3.10 or newer is required"}\n')
        return 2
    source_root = Path(__file__).resolve().parent / "src"
    if (source_root / "traceatlas" / "osint_cli.py").is_file():
        sys.path.insert(0, str(source_root))
    try:
        from traceatlas.osint_cli import main as cli_main
    except ImportError:
        sys.stderr.write('{"status":"ERROR","error":"Install TraceAtlas with python -m pip install . from the repository root, or keep this launcher beside src"}\n')
        return 2
    return cli_main()


if __name__ == "__main__":
    raise SystemExit(main())
