"""Minimal VPN test server.

Binds a TCP port, listens, and accepts connections from the VPN client
(``Client/vpn.py``) in either proxy or tunnel mode. It is deliberately simple:
its job is to prove the client can establish a connection and forward traffic.

Two behaviours are supported per connection, selectable with ``--mode``:

echo (default)
    Everything received is written straight back to the sender. This works for
    both client modes:
      * Proxy mode streams raw bytes, so the client sees its bytes echoed.
      * Tunnel mode sends length-prefixed frames; echoing the exact bytes back
        preserves the framing, so the client's inbound loop can parse them.

drain
    Received bytes are logged and discarded (no reply). Useful when you only
    want to confirm the client is forwarding data.

Usage::

    python Server/server.py                 # echo on 0.0.0.0:9000
    python Server/server.py --port 9000 --mode echo
    python Server/server.py --mode drain

This is a plaintext, unauthenticated test server. Do not expose it to an
untrusted network; bind it to localhost or a trusted LAN only.
"""

from __future__ import annotations

import argparse
import logging
import socket
import sys
import threading

# Reuse the client's config for defaults when it is importable; otherwise fall
# back to hard-coded values so the server can run standalone.
try:  # pragma: no cover - import convenience
    import config  # type: ignore

    _DEFAULT_PORT = config.SERVER_PORT
    _BUFFER = config.SOCKET_BUFFER_SIZE
except Exception:  # pragma: no cover
    _DEFAULT_PORT = 9000
    _BUFFER = 65535


log = logging.getLogger("vpn-server")


def _setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%H:%M:%S",
    )


class VPNServer:
    """Threaded TCP server that accepts and services client connections."""

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = _DEFAULT_PORT,
        mode: str = "echo",
        backlog: int = 128,
    ) -> None:
        if mode not in ("echo", "drain"):
            raise ValueError(f"Unknown mode {mode!r} (expected 'echo' or 'drain')")
        self.host = host
        self.port = port
        self.mode = mode
        self.backlog = backlog

        self._sock: socket.socket | None = None
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self.clients_served = 0
        self.bytes_received = 0

    # -- lifecycle ------------------------------------------------------- #
    def start(self) -> None:
        """Bind, listen, and accept connections until :meth:`stop`."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(self.backlog)
        sock.settimeout(0.5)  # so the accept loop can observe the stop flag
        self._sock = sock
        self._stop.clear()
        log.info("VPN server listening on %s:%s (mode=%s)", self.host, self.port, self.mode)

        try:
            self._accept_loop()
        except KeyboardInterrupt:  # pragma: no cover - interactive
            log.info("Interrupted — shutting down")
        finally:
            self.stop()

    def _accept_loop(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self.clients_served += 1
            log.info("Accepted connection from %s:%s", *addr)
            t = threading.Thread(
                target=self._handle_client,
                args=(conn, addr),
                name=f"client-{addr[1]}",
                daemon=True,
            )
            t.start()
            self._threads.append(t)

    def _handle_client(self, conn: socket.socket, addr) -> None:
        """Service one connection according to the configured mode."""
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        total = 0
        try:
            while not self._stop.is_set():
                data = conn.recv(_BUFFER)
                if not data:
                    break
                total += len(data)
                self.bytes_received += len(data)
                if self.mode == "echo":
                    conn.sendall(data)
        except OSError as exc:
            log.debug("Client %s:%s error: %s", addr[0], addr[1], exc)
        finally:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            conn.close()
            log.info("Closed %s:%s (received %d bytes)", addr[0], addr[1], total)

    def stop(self) -> None:
        """Stop accepting and close the listening socket."""
        if self._stop.is_set():
            return
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        log.info(
            "Server stopped — clients_served=%d bytes_received=%d",
            self.clients_served,
            self.bytes_received,
        )


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Minimal VPN test server.")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=_DEFAULT_PORT,
                        help=f"Bind port (default: {_DEFAULT_PORT})")
    parser.add_argument("--mode", choices=("echo", "drain"), default="echo",
                        help="Per-connection behaviour (default: echo)")
    parser.add_argument("--log-level", default="INFO", help="Logging level")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    _setup_logging(args.log_level)
    server = VPNServer(host=args.host, port=args.port, mode=args.mode)
    try:
        server.start()
    except OSError as exc:
        log.error("Could not start server: %s", exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
