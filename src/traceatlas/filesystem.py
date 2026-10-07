"""Filesystem boundaries for identifiers and files within a trusted local root.

Workspace/output roots are still chosen explicitly by the local operator. An
imported identifier or record may only choose a child within that root.
"""
from __future__ import annotations

import os
from pathlib import Path


def path_component(value: str) -> str:
    """Reject path syntax on either platform; never silently truncate an ID."""
    if (not isinstance(value, str) or not value or len(value) > 255
            or value in {".", ".."} or any(ord(c) < 32 for c in value)
            or any(c in value for c in "/\\:") or value.rstrip(" .") != value):
        raise ValueError("Invalid filesystem identifier")
    if value.split('.')[0].upper() in {'CON', 'PRN', 'AUX', 'NUL',
            *(f'COM{i}' for i in range(1, 10)), *(f'LPT{i}' for i in range(1, 10))}:
        raise ValueError("Reserved filesystem identifier")
    # The returned basename is identical to the validated input. Using it also
    # makes the boundary explicit to static data-flow analysis.
    return os.path.basename(value)


def child_path(root: Path, name: str) -> Path:
    """One child, with symlink escape rejected before reading or writing."""
    root = Path(root)
    child = root / path_component(name)
    if child.is_symlink() or child.resolve().parent != root.resolve():
        raise ValueError("Unsafe workspace child")
    return child


def checked_local_path(path: Path) -> Path:
    """Reject symlinks in an already-confined path before optional-store I/O.

    This does not authorize an arbitrary root or protect against a hostile
    operating-system user replacing directories concurrently.
    """
    path = Path(path).absolute()
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("Symlinked local storage is unsupported")
    return path
