"""Pytest / unittest network guard — CI must never hit real LLM APIs."""

from __future__ import annotations

import socket
from typing import Iterable, Set

import pytest

# Hosts that unit tests may still reach (none by default).
_ALLOWLIST: Set[str] = {
    "localhost",
    "127.0.0.1",
    "::1",
}

_original_connect = socket.socket.connect


def _guarded_connect(self, address):  # type: ignore[no-untyped-def]
    host = address[0] if isinstance(address, tuple) else address
    if isinstance(host, bytes):
        host = host.decode("utf-8", errors="replace")
    host_str = str(host).split("%")[0]
    if host_str not in _ALLOWLIST:
        raise RuntimeError(
            f"Network blocked in tests: attempted connect to {address!r}. "
            "Mock provider/HTTP clients instead of making real API calls."
        )
    return _original_connect(self, address)


@pytest.fixture(autouse=True)
def _block_external_network():
    socket.socket.connect = _guarded_connect  # type: ignore[method-assign]
    try:
        yield
    finally:
        socket.socket.connect = _original_connect  # type: ignore[method-assign]


# Also apply for unittest discovery when pytest loads this module.
socket.socket.connect = _guarded_connect  # type: ignore[method-assign]
