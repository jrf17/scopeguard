"""Shared fixtures. The lab server binds loopback only."""

from __future__ import annotations

import importlib.util
import threading
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]


def load_fixture_module():
    path = ROOT / "lab" / "fixture_app.py"
    spec = importlib.util.spec_from_file_location("scopeguard_fixture_app", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def lab() -> Iterator[Callable[[str], object]]:
    module = load_fixture_module()
    servers: list[object] = []

    def start(mode: str = "vulnerable"):
        server = module.serve(mode, "127.0.0.1", 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append(server)
        return server

    yield start
    for server in servers:
        server.shutdown()
        server.server_close()


def base_config(**overrides: object) -> dict[str, object]:
    data: dict[str, object] = {
        "name": "test",
        "hosts": [{"host": "127.0.0.1", "scheme": "http", "ports": [8765]}],
        "path_prefixes": ["/"],
        "limits": {"timeout_seconds": 2, "concurrency": 1, "rate_limit_rps": 20},
        "recon": ["http"],
        "checks": [],
        "allow_loopback": True,
        "allow_private": False,
        "allow_public": False,
    }
    data.update(overrides)
    return data


def clock() -> Callable[[], str]:
    counter = {"n": 0}

    def _now() -> str:
        counter["n"] += 1
        return f"2026-01-01T00:00:{counter['n']:02d}Z"

    return _now
