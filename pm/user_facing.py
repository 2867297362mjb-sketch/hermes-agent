"""PATH for children a person or the agent drives (terminal commands, MCP servers).

A sealed Windows payload's store sits under ``WindowsApps``. In the process tree that the
app's execution alias starts, a program whose own executable is outside the package cannot
start one inside it. cmd.exe running npm's ``npx.cmd`` gets "Access is denied" from the
packaged ``node.exe``, and a venv's ``Scripts\\python.exe`` redirector exits 101 when it
starts the packaged Python. A copy of the same files outside the package starts without
error. In-package programs (the payload's Python and bash) start the packaged executables
too, so Hermes's own children keep the store-first PATH that ``pm.install.activate`` writes.
Terminal commands and MCP servers run any host program, so they get
:func:`user_facing_path` instead.
"""
from __future__ import annotations

import logging
import os

LOG = logging.getLogger(__name__)

# A host install of these comes before the payload's copy. Python is not in this list: on a
# machine without Python, the first ``python.exe`` on PATH is the Microsoft Store stub alias.
# npm comes first: node's own dir also holds an npx, for node's bundled npm, not the pinned one.
HOST_FIRST = ("npm", "node")
# User-facing children get PM's verified copy of these outside the package.
COPIED = (*HOST_FIRST, "python")


def applies() -> bool:
    """True for a sealed payload on Windows, the only layout with the restriction above."""
    from pm.install import sealed
    from pm.store import current_target

    return current_target().startswith("win32") and sealed()


def writable_copy(name: str, *, realize: bool = True, explicit: bool = False,
                  why: str = "a copy outside the package is required"):
    """``(facts, store)`` of PM's verified copy of the installed *name* in the writable store.

    The first call copies the installed entry and checks its digest. It downloads nothing.
    If the install already lives in the writable store, that install is the answer. Returns
    ``None`` when *name* is not installed, or when no copy exists and *realize* is false.
    Raises the lazy-install refusal, naming *why*, when a copy is needed and lazy installs
    are off.
    """
    from pm import paths
    from pm.filesystem import long_root
    from pm.install import _install, _installed_location, _lockfile, _refuse_lazy, lazy_installs_allowed
    from pm.lock import Facts
    from pm.registry import get_package
    from pm.store import Store, current_target

    package, lockfile, target = get_package(name), _lockfile(), current_target()
    location = _installed_location(package, lockfile, target)
    if location is None:
        return None
    # Spelled like Store spells its root, so the comparison and the copy's file calls agree.
    writable = long_root(paths.writable_store_root())
    if location[1].root == writable:
        return location
    copied = _installed_location(package, lockfile, target, verify=explicit, roots=(writable,))
    if copied is not None or not realize:
        return copied
    if not explicit and not lazy_installs_allowed():
        raise _refuse_lazy(name, why)
    copy_store, copy_facts = Store(writable), Facts(writable / "facts.json")
    _install(package, lockfile, copy_facts, copy_store, target, copy_from=location)
    return copy_facts, copy_store


def _dirs(facts, store, name: str) -> list[str]:
    """The PATH dirs that *store*'s install of *name* contributes, natively spelled."""
    from pm.filesystem import native

    dirs = facts.env_for(name, store.root).get("PATH") or []
    return [native(d) for d in ([dirs] if isinstance(dirs, str) else dirs) if d]


def _sealed_dirs(name: str) -> list[str]:
    from pm.install import _facts, _store

    facts, store = _facts(), _store()
    return _dirs(facts, store, name) if facts.installed(name, None, store.root) else []


def _copy_dirs(name: str) -> list[str]:
    """The PATH dirs of *name*'s writable copy, made on first use, or ``[]`` when PM may not make one."""
    from pm.package import InstallError

    try:
        location = writable_copy(name)
    except (InstallError, OSError) as exc:
        LOG.debug("user-facing %s stays the packaged copy: %s", name, exc)
        return []
    return _dirs(*location, name) if location is not None else []


def user_facing_path(path: str) -> str:
    """*path* for a user-facing child. Unchanged off a sealed Windows payload.

    Each packaged node, npm and python dir is replaced by its writable copy. The node and npm
    dirs then move to the end, so a host Node wins. A packaged dir stays when PM may not copy
    it (lazy installs off), as the fallback for a machine without a host install.
    """
    if not applies():
        return path
    swap: dict[str, list[str]] = {}
    tail: list[str] = []
    for name in COPIED:
        sealed = _sealed_dirs(name)
        dirs = (_copy_dirs(name) if sealed else []) or sealed
        for directory in sealed:
            swap[os.path.normcase(directory)] = [] if name in HOST_FIRST else dirs
        if name in HOST_FIRST:
            tail.extend(dirs)
    tail_keys = {os.path.normcase(d) for d in tail}
    entries = [d for p in path.split(os.pathsep) if p for d in swap.get(os.path.normcase(p), [p])]
    kept = [d for d in entries if os.path.normcase(d) not in tail_keys]
    return os.pathsep.join(dict.fromkeys([*kept, *tail]))
