"""Small cross-platform mock service lab for scanner testing.

Creates several harmless local TCP listeners that imitate common service
banners/headers. It does NOT implement the real protocols beyond the minimum
responses needed by scanner_Service_Fingerprint.py.

Examples:
    # Safe local-only mode
    python mock_services_lab.py

    # End-to-end test with a scanner that targets this computer's LAN IP
    python mock_services_lab.py --host 0.0.0.0

Then scan the explicit test ports, for example:
    python scanner_Service_Fingerprint.py --ports 18022,18080,18081,18082,18083,18121,18122,18123,18225,18226

Only expose these mock listeners on networks you are authorized to test.
"""

from __future__ import annotations

import argparse
import socketserver
import threading
from dataclasses import dataclass
from typing import Dict, List, Tuple, Type


@dataclass(frozen=True)
class MockService:
    port: int
    service: str
    product: str
    version: str
    handler_name: str


class ThreadingTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class QuietHandler(socketserver.BaseRequestHandler):
    """Base handler with small helpers and no per-connection console noise."""

    timeout = 2.0

    def setup(self) -> None:
        self.request.settimeout(self.timeout)

    def recv_some(self, size: int = 4096) -> bytes:
        try:
            return self.request.recv(size)
        except (TimeoutError, OSError):
            return b""

    def send(self, data: bytes) -> None:
        try:
            self.request.sendall(data)
        except OSError:
            pass


class SSHHandler(QuietHandler):
    def handle(self) -> None:
        self.send(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n")
        self.recv_some()


class ApacheHTTPHandler(QuietHandler):
    def handle(self) -> None:
        self.recv_some()
        self.send(
            b"HTTP/1.1 200 OK\r\n"
            b"Server: Apache/2.4.58\r\n"
            b"Content-Length: 0\r\n"
            b"Connection: close\r\n\r\n"
        )


class NginxHTTPHandler(QuietHandler):
    def handle(self) -> None:
        self.recv_some()
        self.send(
            b"HTTP/1.1 200 OK\r\n"
            b"Server: nginx/1.24.0\r\n"
            b"Content-Length: 0\r\n"
            b"Connection: close\r\n\r\n"
        )


class IISHTTPHandler(QuietHandler):
    def handle(self) -> None:
        self.recv_some()
        self.send(
            b"HTTP/1.1 200 OK\r\n"
            b"Server: Microsoft-IIS/10.0\r\n"
            b"Content-Length: 0\r\n"
            b"Connection: close\r\n\r\n"
        )


class PythonHTTPHandler(QuietHandler):
    def handle(self) -> None:
        self.recv_some()
        self.send(
            b"HTTP/1.1 200 OK\r\n"
            b"Server: SimpleHTTP/0.6 Python/3.14.7\r\n"
            b"Content-Length: 0\r\n"
            b"Connection: close\r\n\r\n"
        )


class VsFTPdHandler(QuietHandler):
    def handle(self) -> None:
        self.send(b"220 (vsFTPd 3.0.5)\r\n")
        self.recv_some()


class ProFTPDHandler(QuietHandler):
    def handle(self) -> None:
        self.send(b"220 ProFTPD Server (Mock Lab) 1.3.8\r\n")
        self.recv_some()


class FileZillaHandler(QuietHandler):
    def handle(self) -> None:
        self.send(b"220-FileZilla Server 1.8.2\r\n220 Mock service ready\r\n")
        self.recv_some()


class PostfixSMTPHandler(QuietHandler):
    def handle(self) -> None:
        self.send(b"220 mock.local ESMTP Postfix\r\n")
        request = self.recv_some()
        if request.upper().startswith((b"EHLO", b"HELO")):
            self.send(
                b"250-mock.local\r\n"
                b"250-PIPELINING\r\n"
                b"250-SIZE 10240000\r\n"
                b"250 HELP\r\n"
            )


class MicrosoftSMTPHandler(QuietHandler):
    def handle(self) -> None:
        self.send(b"220 mock.local Microsoft ESMTP MAIL Service ready\r\n")
        request = self.recv_some()
        if request.upper().startswith((b"EHLO", b"HELO")):
            self.send(
                b"250-mock.local Hello\r\n"
                b"250-SIZE 10485760\r\n"
                b"250 HELP\r\n"
            )


HANDLERS: Dict[str, Type[QuietHandler]] = {
    "ssh": SSHHandler,
    "apache": ApacheHTTPHandler,
    "nginx": NginxHTTPHandler,
    "iis": IISHTTPHandler,
    "python_http": PythonHTTPHandler,
    "vsftpd": VsFTPdHandler,
    "proftpd": ProFTPDHandler,
    "filezilla": FileZillaHandler,
    "postfix": PostfixSMTPHandler,
    "ms_smtp": MicrosoftSMTPHandler,
}


SERVICES: Tuple[MockService, ...] = (
    MockService(18022, "ssh", "OpenSSH", "9.6p1", "ssh"),
    MockService(18080, "http", "Python http.server", "3.14.7", "python_http"),
    MockService(18081, "http", "Apache httpd", "2.4.58", "apache"),
    MockService(18082, "http", "nginx", "1.24.0", "nginx"),
    MockService(18083, "http", "Microsoft IIS", "10.0", "iis"),
    MockService(18121, "ftp", "vsFTPd", "3.0.5", "vsftpd"),
    MockService(18122, "ftp", "ProFTPD", "1.3.8", "proftpd"),
    MockService(18123, "ftp", "FileZilla Server", "1.8.2", "filezilla"),
    MockService(18225, "smtp", "Postfix", "banner only", "postfix"),
    MockService(18226, "smtp", "Microsoft ESMTP", "banner only", "ms_smtp"),
)


def parse_ports(value: str | None) -> set[int] | None:
    if value is None:
        return None

    ports: set[int] = set()
    for token in value.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            port = int(token)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"Invalid port: {token}") from exc
        if not 1 <= port <= 65535:
            raise argparse.ArgumentTypeError(f"Port out of range: {port}")
        ports.add(port)
    return ports


def start_services(host: str, selected_ports: set[int] | None) -> List[ThreadingTCPServer]:
    servers: List[ThreadingTCPServer] = []

    for service in SERVICES:
        if selected_ports is not None and service.port not in selected_ports:
            continue

        handler = HANDLERS[service.handler_name]
        try:
            server = ThreadingTCPServer((host, service.port), handler)
        except OSError as exc:
            print(f"[!] Could not bind {host}:{service.port}: {exc}")
            continue

        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append(server)

    return servers


def print_table(host: str, servers: List[ThreadingTCPServer]) -> None:
    running_ports = {int(server.server_address[1]) for server in servers}

    print()
    print(f"Mock service lab listening on {host}")
    print()
    print(f"{'PORT':<8} {'SERVICE':<10} {'PRODUCT':<22} {'VERSION'}")
    print("-" * 60)
    for service in SERVICES:
        if service.port in running_ports:
            print(
                f"{service.port:<8} "
                f"{service.service:<10} "
                f"{service.product:<22} "
                f"{service.version}"
            )

    port_list = ",".join(str(port) for port in sorted(running_ports))
    print()
    print("Scanner test command:")
    print(f"  python scanner_Service_Fingerprint.py --ports {port_list}")
    print()
    print("Press Ctrl+C to stop all mock services.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run harmless mock TCP services for vulnerability-scanner testing."
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help=(
            "Address to bind (default: 127.0.0.1). Use 0.0.0.0 only when "
            "you intentionally want the mocks reachable through this host's LAN IP."
        ),
    )
    parser.add_argument(
        "--ports",
        help="Optional comma-separated subset of mock ports to start.",
    )
    args = parser.parse_args()

    selected_ports = parse_ports(args.ports)
    servers = start_services(args.host, selected_ports)

    if not servers:
        raise SystemExit("No mock services could be started.")

    print_table(args.host, servers)

    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        print("\n[*] Stopping mock services...")
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
