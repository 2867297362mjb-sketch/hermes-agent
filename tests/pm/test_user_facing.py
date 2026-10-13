"""User-facing children of a sealed Windows payload get tools they can start (pm.user_facing)."""
from __future__ import annotations

import os

import pytest

from pm.lock import Facts, Lockfile
from pm.packages import Nodejs, Python
from pm.store import current_target, tree_digest


@pytest.fixture
def sealed_payload(tmp_path, monkeypatch):
    """A shipped store holding node and python, beside a separate writable store."""
    import pm.user_facing
    from pm import paths, registry

    shipped, writable = tmp_path / "payload" / "tools", tmp_path / "home" / "tools"
    target, digest = current_target(), "1" * 64
    lock = Lockfile(tmp_path / "lock.json")
    facts = Facts(shipped / "facts.json")
    for package in (Nodejs(), Python()):
        package.verify = lambda entry, target: ""
        monkeypatch.setitem(registry._packages, package.name, package)
        lock.set_pin(package.name, "test", {target: {"url": "https://test.invalid", "sha256": digest}})
        entry = shipped / package.store_entry("test", target)
        binary = package.binary(entry, target)
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b"pinned " + package.name.encode())
        facts.record(package.name, "test", entry.name, package.env(entry, target), shipped,
                     target=target, artifacts=[digest], digest=tree_digest(entry))
    lock.save()
    monkeypatch.setattr(paths, "lockfile_path", lambda: lock.path)
    monkeypatch.setattr(paths, "store_root", lambda: shipped)
    monkeypatch.setattr(paths, "writable_store_root", lambda: writable)
    monkeypatch.setattr(pm.user_facing, "applies", lambda: True)
    return shipped, writable


def test_packaged_tools_become_writable_copies_and_node_goes_last(sealed_payload, monkeypatch):
    import pm.install
    from pm.packages import Nodejs, Python
    from pm.user_facing import user_facing_path

    shipped, writable = sealed_payload
    target = current_target()

    def bin_dir(root, package):
        return str(package.binary(root / package.store_entry("test", target), target).parent)

    path = os.pathsep.join([bin_dir(shipped, Python()), bin_dir(shipped, Nodejs()), "/usr/bin"])

    # Lazy installs off: no copy, so the packaged dirs stay as the fallback.
    monkeypatch.setattr(pm.install, "lazy_installs_allowed", lambda: False)
    assert user_facing_path(path).split(os.pathsep) == [
        bin_dir(shipped, Python()), "/usr/bin", bin_dir(shipped, Nodejs())]
    assert not writable.exists()

    monkeypatch.setattr(pm.install, "lazy_installs_allowed", lambda: True)
    copied = user_facing_path(path)
    assert copied.split(os.pathsep) == [bin_dir(writable, Python()), "/usr/bin", bin_dir(writable, Nodejs())]
    assert user_facing_path(copied) == copied
