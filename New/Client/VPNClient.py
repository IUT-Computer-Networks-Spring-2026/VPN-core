"""VPNClient: high-level client orchestration.

Ties together the existing project components:
  - Load_balancer_client.load_balancer_client  -> discover a server
  - VPNPacket.ClientVPNPacket                  -> build/parse control+data packets
  - NAT.ClientNAT                              -> source-NAT tunnel traffic
  - Tunnel.Tunnel                              -> Wintun virtual adapter (Windows)
  - Crypto.Cesar                               -> encode/decode everything on the wire

Connection flow (see connect()):
  1. Ask the load balancer for (server_ip, server_port).
  2. TCP-connect over the physical NIC, authenticate (or register first).
  3. Send GET_IP and receive ASSIGN_IP -> the private tunnel address.
  4. Bring up the Wintun tunnel on that address and bypass-route the server IP.
  5. Re-connect a data socket (auth again), init ClientNAT, and run three worker
     threads (send / receive / keep-alive).
  6. GET_NEW_IP or a fatal error triggers a full reconnect, up to 3 attempts.

The `Tunnel` class is Windows-only and needs administrator rights, so it is
imported lazily and can be replaced through `tunnel_factory` for testing.
"""

import random
import socket
import threading
import time
from typing import Callable, List, Optional, Tuple

from Crypto import Cesar
from NAT import ClientNAT
from VPNPacket import (
    ClientVPNPacket,
    InvalidVPNPacketError,
    CODE_DATA,
    CODE_KEEP_ALIVE,
    CODE_DISCONNECT,
    CODE_ERROR,
    CODE_ASSIGN_IP,
    CODE_GET_NEW_IP,
    CODE_AUTH_SUCCESS,
    CODE_AUTH_FAILED,
    CODE_REGISTER_SUCCESS,
    CODE_QUOTA_RESPONSE,
)
from Load_balancer_client import load_balancer_client


MAX_DATA_PAYLOAD = 65530
SOCKET_TIMEOUT = 1.0
KEEPALIVE_IDLE = 180
KEEPALIVE_TICK = 180
MAX_RETRIES = 3


# --------------------------------------------------------------------------- #
# Exceptions
# --------------------------------------------------------------------------- #
class VPNClientError(Exception):
    """Base class for all client-side failures."""


class ConnectionSetupError(VPNClientError):
    """Raised when the initial handshake with the server fails."""


class ReconnectExhaustedError(VPNClientError):
    """Raised when all reconnect attempts have been used up."""


class ServerError(VPNClientError):
    """Raised when the server reports an ERROR packet during handshake."""


class AuthError(VPNClientError):
    """Raised when authentication or registration is rejected by the server."""


# --------------------------------------------------------------------------- #
# Wire framing helper: every frame is Cesar-encoded on the socket.
# --------------------------------------------------------------------------- #
class _Stopped(Exception):
    """Internal signal: a worker was asked to stop while blocked on I/O."""


class _FrameReader:
    """Buffers a TCP stream and yields whole (decrypted) VPN packets."""

    def __init__(self, sock: socket.socket):
        self._sock = sock
        self._buf = bytearray()

    def _fill(self, should_stop: Callable[[], bool]) -> bool:
        while True:
            if should_stop():
                raise _Stopped()
            try:
                chunk = self._sock.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                return False
            if not chunk:
                return False
            self._buf.extend(chunk)
            return True

    def read_packet(self, should_stop: Callable[[], bool]) -> Optional[bytes]:
        while len(self._buf) < 4:
            if not self._fill(should_stop):
                return None
        header = Cesar.decode(bytes(self._buf[:4]))
        payload_len = int.from_bytes(header[:2], "big")
        total = 4 + payload_len
        while len(self._buf) < total:
            if not self._fill(should_stop):
                return None
        frame = bytes(self._buf[:total])
        del self._buf[:total]
        return Cesar.decode(frame)


def _send_frame(sock: socket.socket, packet: bytes) -> None:
    sock.sendall(Cesar.encode(packet))


def _fragment(payload: bytes) -> List[Tuple[bytes, bool]]:
    if len(payload) <= MAX_DATA_PAYLOAD:
        return [(payload, False)]
    chunks: List[Tuple[bytes, bool]] = []
    for i in range(0, len(payload), MAX_DATA_PAYLOAD):
        piece = payload[i:i + MAX_DATA_PAYLOAD]
        more = (i + MAX_DATA_PAYLOAD) < len(payload)
        chunks.append((piece, more))
    return chunks


# --------------------------------------------------------------------------- #
# VPNClient
# --------------------------------------------------------------------------- #
class VPNClient:
    """Orchestrates a full client VPN session with authentication + reconnect."""

    def __init__(
        self,
        username: str,
        password: str,
        adapter_name: str = "VPNcore",
        tunnel_factory: Optional[Callable[[], object]] = None,
        lb_ask: Optional[Callable[[], Tuple[str, int]]] = None,
    ):
        self.username = username
        self.password = password
        self.adapter_name = adapter_name
        self._tunnel_factory = tunnel_factory or _default_tunnel_factory
        self._lb_ask = lb_ask or _default_lb_ask

        self.server_ip: str = ""
        self.server_port: int = 0
        self.assigned_ip: str = ""
        self.session_id: int = 0

        self._tunnel = None
        self._sock: Optional[socket.socket] = None
        self._nat: Optional[ClientNAT] = None
        self._local_port: Optional[int] = None
        self._packet = ClientVPNPacket()

        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._last_activity = 0.0
        self._threads: List[threading.Thread] = []
        self._reader: Optional[_FrameReader] = None
        self._reasm: dict = {}

        self._reconnect_requested = threading.Event()
        self._retries_left = MAX_RETRIES

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def register(self) -> None:
        """Register this username/password with the server (one-shot)."""
        self.server_ip, self.server_port = self._lb_ask()
        self.session_id = random.randint(0, 7)
        temp = socket.create_connection((self.server_ip, self.server_port), timeout=10)
        try:
            temp.settimeout(10)
            _send_frame(temp, self._packet.build_register_request(
                self.session_id, self.username, self.password))
            reader = _FrameReader(temp)
            packet = reader.read_packet(lambda: False)
            if packet is None:
                raise ConnectionSetupError("Server closed connection during registration")
            parsed = self._packet.parse(packet)
            if parsed.code == CODE_REGISTER_SUCCESS:
                return
            if parsed.code == CODE_ERROR:
                raise AuthError(parsed.error_message or "Registration failed")
            raise ConnectionSetupError(f"Unexpected registration response {parsed.code_name}")
        finally:
            temp.close()

    def connect(self) -> None:
        """Discover a server, authenticate, establish the tunnel, start workers."""
        self.server_ip, self.server_port = self._lb_ask()
        self._retries_left = MAX_RETRIES
        self._establish()

    def request_quota(self, requested_bytes: int) -> None:
        """Ask the server to add quota (billing hook lives server-side)."""
        if self._sock is None:
            raise VPNClientError("Not connected")
        _send_frame(self._sock, self._packet.build_quota_request(self.session_id, requested_bytes))

    def disconnect(self) -> None:
        """Gracefully tear down: stop threads, socket and tunnel."""
        if self._stop_event.is_set() and not self._threads:
            return
        self._stop_event.set()
        if self._sock is not None:
            try:
                _send_frame(self._sock, self._packet.build_disconnect(self.session_id))
            except OSError:
                pass
        self._join_threads()
        self._close_socket()
        self._close_tunnel()
        self._nat = None

    def wait(self) -> None:
        while self._threads and any(t.is_alive() for t in self._threads):
            time.sleep(0.2)

    @property
    def is_connected(self) -> bool:
        return bool(self._threads) and not self._stop_event.is_set()

    # ------------------------------------------------------------------ #
    # Connection establishment (with retry)
    # ------------------------------------------------------------------ #
    def _establish(self) -> None:
        last_error: Optional[Exception] = None
        while self._retries_left > 0:
            self._retries_left -= 1
            try:
                assigned_ip = self._handshake_get_ip()
            except _NeedNewIP:
                continue
            except AuthError:
                raise  # auth failures are terminal, no point retrying
            except (OSError, InvalidVPNPacketError, ServerError) as exc:
                last_error = exc
                continue

            try:
                self._bring_up_tunnel(assigned_ip)
                self._open_data_connection()
                self._reset_state()
                self._start_threads()
                return
            except AuthError:
                self._close_socket()
                self._close_tunnel()
                raise
            except Exception as exc:
                last_error = exc
                self._close_socket()
                self._close_tunnel()

        if last_error is not None:
            raise ReconnectExhaustedError(
                f"Could not establish VPN session after {MAX_RETRIES} attempts: {last_error}"
            )
        raise ReconnectExhaustedError(
            f"Server kept requesting a new IP; gave up after {MAX_RETRIES} attempts"
        )

    def _authenticate(self, sock: socket.socket, reader: _FrameReader) -> None:
        """Send AUTH_REQUEST and require AUTH_SUCCESS. Raises AuthError otherwise."""
        _send_frame(sock, self._packet.build_auth_request(
            self.session_id, self.username, self.password))
        packet = reader.read_packet(lambda: False)
        if packet is None:
            raise ConnectionSetupError("Server closed connection during authentication")
        parsed = self._packet.parse(packet)
        if parsed.code == CODE_AUTH_SUCCESS:
            return
        if parsed.code == CODE_AUTH_FAILED:
            raise AuthError("Authentication failed")
        if parsed.code == CODE_ERROR:
            raise AuthError(parsed.error_message or "Authentication rejected")
        raise ConnectionSetupError(f"Unexpected auth response {parsed.code_name}")

    def _handshake_get_ip(self) -> str:
        """Auth over a temp socket, send GET_IP, return the assigned IP string."""
        self.session_id = random.randint(0, 7)
        temp = socket.create_connection((self.server_ip, self.server_port), timeout=10)
        try:
            temp.settimeout(10)
            reader = _FrameReader(temp)
            self._authenticate(temp, reader)

            _send_frame(temp, self._packet.build_get_ip(self.session_id))
            packet = reader.read_packet(lambda: False)
            if packet is None:
                raise ConnectionSetupError("Server closed connection during handshake")
            parsed = self._packet.parse(packet)

            if parsed.code == CODE_ASSIGN_IP:
                if not parsed.ip:
                    raise ConnectionSetupError("ASSIGN_IP without an address")
                return parsed.ip
            if parsed.code == CODE_GET_NEW_IP:
                raise _NeedNewIP()
            if parsed.code == CODE_ERROR:
                raise ServerError(parsed.error_message or "Server returned ERROR during handshake")
            raise ConnectionSetupError(f"Unexpected handshake response {parsed.code_name}")
        finally:
            temp.close()

    def _bring_up_tunnel(self, assigned_ip: str) -> None:
        self.assigned_ip = assigned_ip
        self._tunnel = self._tunnel_factory()
        self._tunnel.create(self.adapter_name, assigned_ip)
        try:
            self._tunnel.add_bypass(self.server_ip)
        except Exception:
            pass  # bypass is best-effort; a routing loop is caught by timeouts

    def _open_data_connection(self) -> None:
        self._sock = socket.create_connection((self.server_ip, self.server_port), timeout=10)
        self._sock.settimeout(SOCKET_TIMEOUT)
        self._local_port = self._sock.getsockname()[1]
        self._reader = _FrameReader(self._sock)
        # Authenticate the data socket too (server requires creds first).
        self._authenticate(self._sock, self._reader)
        self._nat = ClientNAT(self.assigned_ip, ignored_ports=[self._local_port])
        # ANNOUNCE_IP must be the FIRST packet on the data socket: it tells the
        # server which assigned 10.0.0.x this connection belongs to (the TCP
        # source IP is the physical NIC because the server route is bypassed).
        _send_frame(self._sock, self._packet.build_announce_ip(self.session_id, self.assigned_ip))

    def _reset_state(self) -> None:
        self._stop_event.clear()
        self._reconnect_requested.clear()
        self._reasm.clear()
        with self._lock:
            self._last_activity = time.time()

    # ------------------------------------------------------------------ #
    # Threads
    # ------------------------------------------------------------------ #
    def _start_threads(self) -> None:
        self._threads = [
            threading.Thread(target=self._send_loop, name="vpn-send", daemon=True),
            threading.Thread(target=self._recv_loop, name="vpn-recv", daemon=True),
            threading.Thread(target=self._keepalive_loop, name="vpn-keepalive", daemon=True),
        ]
        for t in self._threads:
            t.start()

    def _touch(self) -> None:
        with self._lock:
            self._last_activity = time.time()

    def _send_loop(self) -> None:
        try:
            while not self._stop_event.is_set():
                try:
                    raw = self._tunnel.receive()
                except Exception:
                    break
                if not raw:
                    continue
                try:
                    translated = self._nat.translate_out(raw)
                except ValueError:
                    continue
                if translated is None:
                    continue
                try:
                    for chunk, more in _fragment(translated):
                        pkt = self._packet.build_data(self.session_id, chunk, more_fragments=more)
                        _send_frame(self._sock, pkt)
                except OSError:
                    break
                self._touch()
        finally:
            self._stop_event.set()

    def _recv_loop(self) -> None:
        try:
            while not self._stop_event.is_set():
                try:
                    packet = self._reader.read_packet(self._stop_event.is_set)
                except _Stopped:
                    break
                except OSError:
                    break
                if packet is None:
                    break
                try:
                    parsed = self._packet.parse(packet)
                except InvalidVPNPacketError:
                    try:
                        _send_frame(self._sock, self._packet.build_error(
                            self.session_id, "Malformed packet"))
                    except OSError:
                        pass
                    continue
                self._touch()
                if not self._handle_incoming(parsed):
                    break
        finally:
            self._stop_event.set()

    def _handle_incoming(self, parsed) -> bool:
        code = parsed.code
        if code == CODE_DATA:
            self._handle_data(parsed)
            return True
        if code == CODE_KEEP_ALIVE:
            return True
        if code == CODE_QUOTA_RESPONSE:
            return True
        if code == CODE_DISCONNECT:
            return False
        if code == CODE_ERROR:
            return False
        if code == CODE_GET_NEW_IP:
            self._request_reconnect()
            return False
        return True

    def _handle_data(self, parsed) -> None:
        buf = self._reasm.get(parsed.session_id, b"") + parsed.payload
        if parsed.mtu_flag:
            self._reasm[parsed.session_id] = buf
            return
        self._reasm.pop(parsed.session_id, None)
        try:
            restored = self._nat.translate_in(buf)
        except ValueError:
            return
        if restored is None:
            return
        try:
            self._tunnel.send(restored)
        except Exception:
            pass

    def _keepalive_loop(self) -> None:
        while not self._stop_event.wait(KEEPALIVE_TICK):
            with self._lock:
                idle = time.time() - self._last_activity
            if idle > KEEPALIVE_IDLE and self._sock is not None:
                try:
                    _send_frame(self._sock, self._packet.build_keep_alive(self.session_id))
                    self._touch()
                except OSError:
                    break

    # ------------------------------------------------------------------ #
    # Reconnect
    # ------------------------------------------------------------------ #
    def _request_reconnect(self) -> None:
        if self._reconnect_requested.is_set():
            return
        self._reconnect_requested.set()
        threading.Thread(target=self._do_reconnect, name="vpn-reconnect", daemon=True).start()

    def _do_reconnect(self) -> None:
        self._stop_event.set()
        self._join_threads(exclude_current=True)
        self._close_socket()
        self._close_tunnel()
        self._nat = None
        try:
            self._establish()
        except (ReconnectExhaustedError, AuthError):
            pass

    # ------------------------------------------------------------------ #
    # Cleanup helpers
    # ------------------------------------------------------------------ #
    def _join_threads(self, exclude_current: bool = False) -> None:
        current = threading.current_thread()
        for t in self._threads:
            if exclude_current and t is current:
                continue
            if t.is_alive():
                t.join(timeout=5)
        self._threads = [t for t in self._threads if t.is_alive()]

    def _close_socket(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        self._reader = None
        self._local_port = None

    def _close_tunnel(self) -> None:
        if self._tunnel is not None:
            try:
                self._tunnel.close()
            except Exception:
                pass
            self._tunnel = None


class _NeedNewIP(Exception):
    """Internal: server asked for a fresh IP during the handshake."""


# --------------------------------------------------------------------------- #
# Default factories (kept out of __init__ so they can be swapped in tests)
# --------------------------------------------------------------------------- #
def _default_tunnel_factory():
    from Tunnel import Tunnel  # lazy: Windows-only, needs wintun.dll + admin
    return Tunnel()


def _default_lb_ask() -> Tuple[str, int]:
    result = load_balancer_client.ask()
    return str(result[0]), int(result[1])


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        sys.exit("usage: VPNClient.py <username> <password>")
    client = VPNClient(sys.argv[1], sys.argv[2])
    try:
        client.connect()
        client.wait()
    except KeyboardInterrupt:
        pass
    finally:
        client.disconnect()
