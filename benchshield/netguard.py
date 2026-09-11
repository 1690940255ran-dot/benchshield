"""Runtime network isolation for the agent (C2 of the Agent-Eval Checklist).

Previously C2 was a config-declared property ("allow_network: false") —
an honor-system flag. This module turns it into an enforced property:

- ``NetworkBlockedError`` — raised by every socket-based API while the
  guard is active, so the agent (and any code it imported) cannot open
  outbound connections, resolve DNS, or bind listeners.
- ``network_blocked()`` — context manager that patches the socket module
  for the duration of the ``with`` block. Works on every platform because
  it operates at the Python API level; no OS privileges required.
- On Linux, ``network_namespace`` support can layer stronger isolation on
  top (see ``eval_worker``): the evaluator subprocess may run under
  ``unshare -n`` for kernel-level isolation. The in-process guard below is
  the portable baseline that runs everywhere.

What is blocked while the guard is active:

- ``socket.socket`` / ``socket.socketpair`` / ``socket.create_connection``
- ``socket.getaddrinfo`` / ``gethostbyname`` / ``gethostbyname_ex`` (DNS)
- ``urllib.request.urlopen`` (it goes through socket underneath, but is
  also patched explicitly for a clearer error message)

The guard is deliberately escape-resistant but not absolute: a native
extension calling the OS socket API directly would bypass it. That is why
the Agent-Eval Checklist still recommends container/namespace isolation
for high-stakes runs; this guard is the defense you get for free,
everywhere, with zero dependencies.
"""
from __future__ import annotations

import contextlib
import socket
from typing import Iterator


class NetworkBlockedError(ConnectionError):
    """Raised when the agent attempts a network operation while the
    C2 network guard is active."""


class _BlockedSocket:
    """Stand-in for socket.socket that refuses every operation."""

    def __init__(self, *args, **kwargs) -> None:
        raise NetworkBlockedError(
            "agent network access is blocked by the evaluation harness (C2)")

    def __getattr__(self, name):  # pragma: no cover - defensive
        raise NetworkBlockedError(
            "agent network access is blocked by the evaluation harness (C2)")


def _blocked(name: str):
    def _raise(*args, **kwargs):
        raise NetworkBlockedError(
            f"{name} is blocked by the evaluation harness (C2)")
    return _raise


_PATCHED_ATTRS = (
    "socket", "socketpair", "create_connection",
    "getaddrinfo", "gethostbyname", "gethostbyname_ex",
)


@contextlib.contextmanager
def network_blocked() -> Iterator[None]:
    """Block all Python-level network access inside this ``with`` block."""
    saved = {name: getattr(socket, name) for name in _PATCHED_ATTRS}
    for name in _PATCHED_ATTRS:
        setattr(socket, name, _BlockedSocket if name == "socket"
                else _blocked(name))
    # urllib goes through socket, but patch it too for a clearer error.
    urllib_saved = None
    try:
        import urllib.request
        urllib_saved = urllib.request.urlopen
        urllib.request.urlopen = _blocked("urllib.request.urlopen")
    except ImportError:  # pragma: no cover
        pass
    try:
        yield
    finally:
        for name, fn in saved.items():
            setattr(socket, name, fn)
        if urllib_saved is not None:
            import urllib.request
            urllib.request.urlopen = urllib_saved


def network_is_blocked() -> bool:
    """Probe helper: True when a plain socket cannot be created."""
    try:
        s = socket.socket()
    except NetworkBlockedError:
        return True
    s.close()
    return False
