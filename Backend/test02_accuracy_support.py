"""Localhost-only fixture utilities shared by TEST-02 automated/manual checks.

No privileged sockets or external network access are required. Fixture servers
bind to ephemeral loopback TCP ports to avoid collisions on CI runners.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Iterable

from mock_services_lab import HANDLERS, SERVICES, QuietHandler, ThreadingTCPServer


@dataclass(frozen=True)
class ServiceExpectation:
    name: str
    port: int
    service: str
    product: str
    version: str | None


class OpaqueHandler(QuietHandler):
    """Returns a banner that provides no known product/version evidence."""

    def handle(self) -> None:
        self.send(b"X-TEST02-OPAQUE-NONSTANDARD-PROTOCOL\r\n")
        self.recv_some()


class LocalFixtureLab:
    """Manage the existing mock-service handlers on temporary loopback ports."""

    def __init__(self, fixture_names: Iterable[str] | None = None) -> None:
        self._selected = set(fixture_names) if fixture_names is not None else None
        self._servers: list[ThreadingTCPServer] = []
        self._threads: list[threading.Thread] = []
        self.fixtures: list[ServiceExpectation] = []

    def __enter__(self) -> LocalFixtureLab:
        try:
            for fixture in SERVICES:
                if self._selected is not None and fixture.handler_name not in self._selected:
                    continue
                self.add_service(
                    fixture.handler_name,
                    HANDLERS[fixture.handler_name],
                    service=fixture.service,
                    product=fixture.product,
                    version=None if fixture.version == "banner only" else fixture.version,
                )
        except Exception:
            self.__exit__(None, None, None)
            raise
        return self

    def add_service(
        self,
        name: str,
        handler: type[QuietHandler],
        *,
        service: str,
        product: str,
        version: str | None,
    ) -> ServiceExpectation:
        server = ThreadingTCPServer(("127.0.0.1", 0), handler)
        self._servers.append(server)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self._threads.append(thread)
        expectation = ServiceExpectation(
            name=name,
            port=int(server.server_address[1]),
            service=service,
            product=product,
            version=version,
        )
        self.fixtures.append(expectation)
        return expectation

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        for server in reversed(self._servers):
            server.shutdown()
            server.server_close()
        for thread in self._threads:
            thread.join(timeout=2.0)
        self._servers.clear()
        self._threads.clear()
