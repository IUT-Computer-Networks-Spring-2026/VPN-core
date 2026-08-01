"""High-level VPN client controller.

Exposes two independent modes that both forward local traffic to a remote
server over TCP:

Proxy mode
    Opens a loopback listener (``127.0.0.1:<port>``). Every accepted client
    connection is relayed to ``(config.SERVER_IP, config.SERVER_PORT)`` and the
    two sockets are bridged transparently (bytes forwarded exactly as they
    arrive). No administrator rights are required.

Tunnel mode
    Brings up the Wintun virtual adapter, assigns its IP and installs the
    high-priority routes, then opens a single TCP connection to the server.
    IP packets pulled from the adapter are framed and forwarded to the server;
    framed packets received from the server are injected back into the OS.
    Requires administrator rights (adapter + routing changes).

Shared logic (connecting to the server, byte relaying, packet framing) lives in
private helper methods so proxy and tunnel modes do not duplicate it.
"""

from __future__ import annotations

import socket
import struct
import threading
from typing import Optional

import config
import elevation
import validator
from adapter import Adapter
from logger import get_logger
from routing import RouteManager


# 4-byte big-endian length prefix used to preserve packet boundaries when
# streaming discrete L3 packets over a TCP connection (tunnel mode).
_LEN_STRUCT = struct.Struct("!I")


class vpn:
    """Controller for proxy and tunnel VPN modes."""

    def __init__(
        self,
        server_ip: Optional[str] = None,
        server_port: Optional[int] = None,
    ) -> None:
        validator.check_os()

        self.log = get_logger("VPNCore")

        # Remote server endpoint (configurable placeholder).
        self.server_ip: str = server_ip if server_ip is not None else config.SERVER_IP
        self.server_port: int = (
            server_port if server_port is not None else config.SERVER_PORT
        )
        validator.validate_host_port(self.server_ip, self.server_port)

        # --- mode flags ----------------------------------------------------
        self.__proxy_mode: bool = False
        self.__tunnel_mode: bool = False

        # --- tunnel state --------------------------------------------------
        self.adapter: Optional[Adapter] = None
        self.rout: Optional[RouteManager] = None
        self._if_index: Optional[int] = None
        self._tunnel_sock: Optional[socket.socket] = None
        self._tunnel_stop = threading.Event()
        self._tunnel_threads: list[threading.Thread] = []

        # --- proxy state ---------------------------------------------------
        self.lb_host: str = config.PROXY_LISTEN_HOST
        self.lb_port: Optional[int] = None
        self._proxy_listener: Optional[socket.socket] = None
        self._proxy_stop = threading.Event()
        self._proxy_thread: Optional[threading.Thread] = None
        self._proxy_conns: list[socket.socket] = []
        self._proxy_lock = threading.Lock()

    # ==================================================================== #
    # Shared helpers
    # ==================================================================== #
    def _connect_to_server(self) -> socket.socket:
        """Open a TCP connection to the configured VPN server.

        Returns a connected socket. Raises ``OSError`` on failure (caller is
        responsible for logging / cleanup).
        """
        self.log.info(
            "Connecting to VPN server %s:%s", self.server_ip, self.server_port
        )
        sock = socket.create_connection(
            (self.server_ip, self.server_port),
            timeout=config.SERVER_CONNECT_TIMEOUT,
        )
        # Switch back to blocking mode for the relay loops.
        sock.settimeout(None)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.log.info("Connected to VPN server %s:%s", self.server_ip, self.server_port)
        return sock

    @staticmethod
    def _close_socket(sock: Optional[socket.socket]) -> None:
        """Best-effort shutdown + close of a socket."""
        if sock is None:
            return
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass

    def _relay_stream(
        self,
        src: socket.socket,
        dst: socket.socket,
        tag: str,
        on_close: Optional[threading.Event] = None,
    ) -> None:
        """Copy bytes from ``src`` to ``dst`` until the connection closes.

        Transparent forwarding: whatever arrives on ``src`` is written to
        ``dst`` unchanged. Used by proxy mode for both directions.
        """
        try:
            while True:
                if on_close is not None and on_close.is_set():
                    break
                data = src.recv(config.SOCKET_BUFFER_SIZE)
                if not data:
                    break  # peer closed
                dst.sendall(data)
        except OSError as exc:
            self.log.debug("Relay %s ended: %s", tag, exc)
        finally:
            # Closing the write side lets the other direction drain and stop.
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    # -- framing (tunnel mode) ------------------------------------------- #
    @staticmethod
    def _send_framed(sock: socket.socket, data: bytes) -> None:
        """Send a length-prefixed frame so packet boundaries survive TCP."""
        sock.sendall(_LEN_STRUCT.pack(len(data)) + data)

    @staticmethod
    def _recv_exactly(sock: socket.socket, n: int) -> Optional[bytes]:
        """Read exactly ``n`` bytes, or ``None`` if the peer closed early."""
        chunks = bytearray()
        while len(chunks) < n:
            chunk = sock.recv(n - len(chunks))
            if not chunk:
                return None
            chunks.extend(chunk)
        return bytes(chunks)

    def _recv_framed(self, sock: socket.socket) -> Optional[bytes]:
        """Receive one length-prefixed frame, or ``None`` when closed."""
        header = self._recv_exactly(sock, _LEN_STRUCT.size)
        if header is None:
            return None
        (length,) = _LEN_STRUCT.unpack(header)
        if length == 0:
            return b""
        return self._recv_exactly(sock, length)

    # ==================================================================== #
    # Proxy mode
    # ==================================================================== #
    def enable_proxy(self, port: int = config.PROXY_LISTEN_PORT) -> bool:
        """Start the loopback proxy listener.

        Binds ``127.0.0.1:<port>`` and, for every accepted connection, opens a
        TCP connection to the server and bridges the two sockets. Returns
        ``True`` on success, ``False`` otherwise.
        """
        try:
            validator.validate_port(port)
        except (TypeError, ValueError) as exc:
            self.log.error("Invalid proxy port: %s", exc)
            return False

        if self.__proxy_mode:
            self.log.error("Proxy mode is already enabled")
            return False

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind((self.lb_host, port))
            listener.listen(config.PROXY_BACKLOG)
        except OSError as exc:
            self.log.error("Failed to bind proxy listener on %s:%s — %s",
                           self.lb_host, port, exc)
            listener.close()
            return False

        self._proxy_listener = listener
        self.lb_port = port
        self._proxy_stop.clear()
        self.__proxy_mode = True

        self._proxy_thread = threading.Thread(
            target=self._proxy_accept_loop,
            name="proxy-accept",
            daemon=True,
        )
        self._proxy_thread.start()

        self.log.info(
            "Proxy mode listening on %s:%s -> forwarding to %s:%s",
            self.lb_host, port, self.server_ip, self.server_port,
        )
        return True

    def _proxy_accept_loop(self) -> None:
        """Accept incoming loopback connections until stopped."""
        assert self._proxy_listener is not None
        listener = self._proxy_listener
        while not self._proxy_stop.is_set():
            try:
                client, addr = listener.accept()
            except OSError:
                break  # listener closed during shutdown
            self.log.info("Proxy accepted connection from %s:%s", *addr)
            worker = threading.Thread(
                target=self._proxy_handle_client,
                args=(client,),
                name=f"proxy-conn-{addr[1]}",
                daemon=True,
            )
            worker.start()
        self.log.debug("Proxy accept loop exited")

    def _proxy_handle_client(self, client: socket.socket) -> None:
        """Bridge one accepted client to a fresh server connection."""
        server_sock: Optional[socket.socket] = None
        try:
            server_sock = self._connect_to_server()
        except OSError as exc:
            self.log.error("Proxy could not reach server: %s", exc)
            self._close_socket(client)
            return

        client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        with self._proxy_lock:
            self._proxy_conns.extend((client, server_sock))

        # Two threads: client->server and server->client.
        up = threading.Thread(
            target=self._relay_stream,
            args=(client, server_sock, "c->s", self._proxy_stop),
            daemon=True,
        )
        down = threading.Thread(
            target=self._relay_stream,
            args=(server_sock, client, "s->c", self._proxy_stop),
            daemon=True,
        )
        up.start()
        down.start()
        up.join()
        down.join()

        self._close_socket(client)
        self._close_socket(server_sock)
        with self._proxy_lock:
            for s in (client, server_sock):
                if s in self._proxy_conns:
                    self._proxy_conns.remove(s)
        self.log.debug("Proxy connection closed")

    def disable_proxy(self) -> None:
        """Stop the proxy listener and close all active connections."""
        if not self.__proxy_mode:
            self.log.error("Proxy mode is already disabled")
            return

        self.log.info("Disabling proxy mode...")
        self._proxy_stop.set()
        self._close_socket(self._proxy_listener)
        self._proxy_listener = None

        with self._proxy_lock:
            conns = list(self._proxy_conns)
            self._proxy_conns.clear()
        for sock in conns:
            self._close_socket(sock)

        if self._proxy_thread and self._proxy_thread.is_alive():
            self._proxy_thread.join(timeout=5)

        self.__proxy_mode = False
        self.lb_port = None
        self.log.info("Proxy mode disabled")

    # ==================================================================== #
    # Tunnel mode
    # ==================================================================== #
    def enable_tunnel(self) -> bool:
        """Bring up the Wintun tunnel and forward its traffic to the server.

        Steps: ensure admin -> create adapter -> assign IP -> install routes
        -> connect to the server -> start the adapter<->server forwarding
        threads. Returns ``True`` on success.
        """
        if self.__tunnel_mode:
            self.log.error("Tunnel mode is already enabled")
            return False

        # Elevation: request admin if we don't already have it.
        if not elevation.is_admin():
            elevation.ensure_admin()
        if not elevation.is_admin():
            self.log.error("User must be admin to enable tunnel mode")
            return False

        try:
            self.adapter = Adapter.create()
            self.adapter.enable_adapter()
            self._if_index = self.adapter.wait_until_ready()
            self.adapter.start_session()

            self.rout = RouteManager()
            self.rout.assign_ip(if_index=self._if_index)
            if self.rout.has_ip(if_index=self._if_index):
                self.log.info(
                    "Verified: %s is assigned to %r (IfIndex=%s).",
                    self.rout.ip_address,
                    self.adapter.name,
                    self._if_index,
                )
            else:
                self.log.error("has_ip() reports no IP on the adapter — aborting.")
                self._teardown_tunnel()
                return False

            self.rout.create_tunnel(if_index=self._if_index)

            # Connect to the server and start pumping packets.
            self._tunnel_sock = self._connect_to_server()
        except Exception as exc:
            self.log.error("Failed to enable tunnel mode: %s", exc)
            self._teardown_tunnel()
            return False

        self._tunnel_stop.clear()
        self.__tunnel_mode = True

        outbound = threading.Thread(
            target=self._tunnel_adapter_to_server,
            name="tunnel-out",
            daemon=True,
        )
        inbound = threading.Thread(
            target=self._tunnel_server_to_adapter,
            name="tunnel-in",
            daemon=True,
        )
        self._tunnel_threads = [outbound, inbound]
        outbound.start()
        inbound.start()

        self.log.info("Tunnel mode active — forwarding to %s:%s",
                      self.server_ip, self.server_port)
        return True

    def _tunnel_adapter_to_server(self) -> None:
        """Read L3 packets from the adapter and forward them (framed)."""
        assert self.adapter is not None and self._tunnel_sock is not None
        while not self._tunnel_stop.is_set():
            try:
                packet = self.adapter.receive_packet()
            except RuntimeError as exc:
                self.log.warning("Adapter receive ended: %s", exc)
                break
            except Exception as exc:
                self.log.error("Adapter receive error: %s", exc)
                break
            if packet is None:
                continue  # timeout — re-check stop flag
            try:
                self._send_framed(self._tunnel_sock, packet)
            except OSError as exc:
                self.log.warning("Server send failed: %s", exc)
                break
        self._tunnel_stop.set()
        self.log.debug("Tunnel adapter->server loop exited")

    def _tunnel_server_to_adapter(self) -> None:
        """Read framed packets from the server and inject them into the OS."""
        assert self.adapter is not None and self._tunnel_sock is not None
        while not self._tunnel_stop.is_set():
            try:
                packet = self._recv_framed(self._tunnel_sock)
            except OSError as exc:
                self.log.warning("Server recv failed: %s", exc)
                break
            if packet is None:
                self.log.info("Server closed the tunnel connection")
                break
            if not packet:
                continue
            try:
                self.adapter.send_packet(packet)
            except Exception as exc:
                self.log.error("Adapter inject failed: %s", exc)
                break
        self._tunnel_stop.set()
        self.log.debug("Tunnel server->adapter loop exited")

    def disable_tunnel(self) -> None:
        """Tear the tunnel down and revert all system changes."""
        if not self.__tunnel_mode:
            self.log.error("Tunnel mode is already disabled")
            return
        self.log.info("Disabling tunnel mode...")
        self._teardown_tunnel()
        self.__tunnel_mode = False
        self.log.info("Tunnel mode disabled")

    def _teardown_tunnel(self) -> None:
        """Stop forwarding threads, revert routes, and close the adapter.

        Safe to call from a partially-initialised state (used both on the
        error path in :meth:`enable_tunnel` and from :meth:`disable_tunnel`).
        """
        self._tunnel_stop.set()

        self._close_socket(self._tunnel_sock)
        self._tunnel_sock = None

        for thread in self._tunnel_threads:
            if thread.is_alive():
                thread.join(timeout=5)
        self._tunnel_threads = []

        if self.rout is not None:
            try:
                self.rout.revert()
            except Exception as exc:
                self.log.error("Error while reverting routes: %s", exc)

        if self.adapter is not None:
            try:
                self.adapter.close()
            except Exception as exc:
                self.log.error("Error while closing adapter: %s", exc)
            self.log.info("Cleanup complete — adapter removed.")

        self.adapter = None
        self.rout = None
        self._if_index = None

    # ==================================================================== #
    # Convenience
    # ==================================================================== #
    @property
    def proxy_enabled(self) -> bool:
        return self.__proxy_mode

    @property
    def tunnel_enabled(self) -> bool:
        return self.__tunnel_mode

    def shutdown(self) -> None:
        """Disable whichever modes are currently active."""
        if self.__proxy_mode:
            self.disable_proxy()
        if self.__tunnel_mode:
            self.disable_tunnel()

    def __enter__(self) -> "vpn":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.shutdown()


# Convenience alias with conventional capitalisation.
Vpn = vpn
VPN = vpn
