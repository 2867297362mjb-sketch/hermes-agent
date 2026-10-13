"""PATH for children a person or the agent drives (terminal commands, MCP servers).

A sealed Windows payload's store sits under ``WindowsApps``. In the process tree that the
app's execution alias starts, a program whose own executable is outside the package cannot
start one inside it. cmd.exe running npm's ``npx.cmd`` gets "Access is denied" from the
packaged ``node.exe``. In-package programs (the payload's Python and bash) start the same
executables without error, so Hermes's own children keep the store-first PATH that
``pm.install.activate`` writes. Terminal commands and MCP servers run any host program, so
they get :func:`user_facing_path` instead.
"""
from __future__ import annotations

import os

# A host install of these comes before the payload's copy. Python is not in this list: on a
# machine without Python, the first ``python.exe`` on PATH is the Microsoft Store stub alias.
# npm comes first: node's own dir also holds an npx, for node's bundled npm, not the pinned one.
HOST_FIRST = ("npm", "node")


def applies() -> bool:
    """True for a sealed payload on Windows, the only layout with the restriction above."""
    from pm.install import sealed
    from pm.store import current_target

    return current_target().startswith("win32") and sealed()


def _sealed_dirs(name: str) -> list[str]:
    """The PATH dirs that the sealed store's install of *name* contributes, natively spelled."""
    from pm.filesystem import native
    from pm.install import _facts, _store

    facts, store = _facts(), _store()
    if not facts.installed(name, None, store.root):
        return []
    dirs = facts.env_for(name, store.root).get("PATH") or []
    return [native(d) for d in ([dirs] if isinstance(dirs, str) else dirs) if d]


def user_facing_path(path: str) -> str:
    """*path* for a user-facing child. Unchanged off a sealed Windows payload.

    The payload's node and npm dirs move to the end, so a host Node wins and the payload's
    stays the fallback for a machine without one.
    """
    if not applies():
        return path
    tail = list(dict.fromkeys(d for name in HOST_FIRST for d in _sealed_dirs(name)))
    keys = {os.path.normcase(d) for d in tail}
    rest = [p for p in path.split(os.pathsep) if p and os.path.normcase(p) not in keys]
    return os.pathsep.join([*rest, *tail])
