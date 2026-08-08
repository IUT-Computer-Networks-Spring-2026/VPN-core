
import ipaddress
import json
import random
import socket
import subprocess
import sys
import threading
import time
from collections import OrderedDict
from typing import Callable, Dict, List, Optional, Set, Tuple

from Crypto import Cesar
from Database import (
    UserDB,
    ALL_USERS,
    STATUS_ACTIVE,
    STATUS_BANNED,
    STATUS_QUOTA_EXHAUSTED,
)
from DNSCache import DNSCache, DNS_PORT
from NAT import ServerNAT
from Packet import IPPacket
from VPNPacket import (
    ServerVPNPacket,
    InvalidVPNPacketError,
    CODE_DATA,
    CODE_KEEP_ALIVE,
    CODE_DISCONNECT,
    CODE_ERROR,
    CODE_GET_IP,
    CODE_AUTH_REQUEST,
    CODE_REGISTER_REQUEST,
    CODE_QUOTA_REQUEST,
    CODE_ANNOUNCE_IP,
    CODE_STATUS,
    hash_password,
)


MAX_DATA_PAYLOAD = 65530
SOCKET_TIMEOUT = 1.0
SERVER_TUNNEL_IP = "10.0.0.1"
SUBNET = "10.0.0.0/24"

RATE_LIMIT_BPS = 1048576
GRACE_WINDOW_SECONDS = 120
ANNOUNCE_TIMEOUT_SECONDS = 30

# Hardcoded admin (never stored in the DB).
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin"


# --------------------------------------------------------------------------- #
# Administrator privileges
# --------------------------------------------------------------------------- #
def _is_admin() -> bool:
    """Return True if the current process has admin (Windows) / root (POSIX)."""
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except AttributeError:
        # Non-Windows: fall back to the effective UID.
        try:
            import os
            return os.geteuid() == 0
        except AttributeError:
            return False
    except Exception:
        return False


def ensure_admin() -> bool:
    """
    Ensure the process is elevated. Raw sockets on Windows (SOCK_RAW /
    IPPROTO_RAW + SIO_RCVALL) require Administrator, otherwise the socket
    constructor fails with WinError 10013.

    If already elevated, return True. If not, relaunch this same script with a
    UAC prompt (Windows) and terminate the current, non-elevated process.
    Mirrors Tunnel._ensure_admin on the client side.
    """
    if _is_admin():
        return True

    if sys.platform != "win32":
        raise VPNServerError(
            "The VPN server needs root privileges for raw sockets. "
            "Re-run with sudo."
        )

    # Relaunch elevated via UAC.
    params = " ".join(f'"{arg}"' for arg in sys.argv)
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command",
         f"Start-Process -FilePath '{sys.executable}' "
         f"-ArgumentList '{params}' -Verb RunAs"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise VPNServerError(
            "Administrator elevation failed: "
            f"{result.stderr.strip() or 'user declined the UAC prompt'}"
        )

    # The elevated copy is now running in a new console; stop this one.
    sys.exit(0)


# --------------------------------------------------------------------------- #
# Exceptions
# --------------------------------------------------------------------------- #
class VPNServerError(Exception):
    """Base class for server-side failures."""


class IPPoolExhaustedError(VPNServerError):
    """No free address left in the 10.0.0.0/24 pool."""


# --------------------------------------------------------------------------- #
# Rate limiting
# --------------------------------------------------------------------------- #
class TokenBucket:
    """Simple thread-safe token bucket. `consume` blocks until tokens exist."""

    def __init__(self, rate_bps: int, stop_check: Callable[[], bool]):
        self._rate = float(rate_bps)
        self._capacity = float(rate_bps)   # 1 second burst
        self._tokens = float(rate_bps)
        self._last = time.monotonic()
        self._lock = threading.Lock()
        self._stop_check = stop_check

    def consume(self, amount: int) -> None:
        amount = float(amount)
        while not self._stop_check():
            with self._lock:
                now = time.monotonic()
                self._tokens = min(
                    self._capacity, self._tokens + (now - self._last) * self._rate
                )
                self._last = now
                if self._tokens >= amount or amount > self._capacity:
                    # Allow oversized frames through once tokens are non-negative
                    # to avoid a permanent stall on a single large packet.
                    self._tokens -= amount
                    return
                deficit = amount - self._tokens
                wait = deficit / self._rate
            time.sleep(min(wait, 0.25))


# --------------------------------------------------------------------------- #
# Wire framing (every frame is Cesar-encoded).
# --------------------------------------------------------------------------- #
class _Stopped(Exception):
    """Internal: worker asked to stop while blocked on I/O."""


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
# Internet gateway abstraction
# --------------------------------------------------------------------------- #
class InternetGateway:
    """Sends translated IP packets out and delivers replies back to `receiver`."""

    def start(self, receiver: Callable[[bytes], None]) -> None:
        raise NotImplementedError

    def send(self, ip_packet: bytes) -> None:
        raise NotImplementedError

    def stop(self) -> None:
        raise NotImplementedError


class RawSocketGateway(InternetGateway):
    """Default gateway using raw sockets. Requires admin/root and OS support."""

    def __init__(self, exit_ip: str):
        self._exit_ip = exit_ip
        self._send_sock: Optional[socket.socket] = None
        self._recv_sock: Optional[socket.socket] = None
        self._receiver: Optional[Callable[[bytes], None]] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    def start(self, receiver: Callable[[bytes], None]) -> None:
        self._receiver = receiver
        self._send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        self._send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        self._recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        self._recv_sock.bind((self._exit_ip, 0))
        if hasattr(socket, "SIO_RCVALL"):  # Windows
            self._recv_sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        self._recv_sock.settimeout(SOCKET_TIMEOUT)

        self._thread = threading.Thread(target=self._recv_loop, name="gw-recv", daemon=True)
        self._thread.start()

    def send(self, ip_packet: bytes) -> None:
        if self._send_sock is None:
            return
        try:
            dst = IPPacket(ip_packet).get_destination()[0]
            self._send_sock.sendto(ip_packet, (dst, 0))
        except (OSError, ValueError):
            pass

    def _recv_loop(self) -> None:
        while not self._stop.is_set():
            try:
                data = self._recv_sock.recv(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            if data and self._receiver:
                self._receiver(data)

    def stop(self) -> None:
        self._stop.set()
        for s in (self._recv_sock, self._send_sock):
            if s is not None:
                try:
                    if s is self._recv_sock and hasattr(socket, "SIO_RCVALL"):
                        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                except OSError:
                    pass
                try:
                    s.close()
                except OSError:
                    pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)


# --------------------------------------------------------------------------- #
# Per-client handler
# --------------------------------------------------------------------------- #
class ClientHandler:
    """Owns one client TCP connection: auth, assignment or data session."""

    def __init__(self, server: "VPNServer", sock: socket.socket, peer_ip: str):
        self._server = server
        self._sock = sock
        self._peer_ip = peer_ip
        self._reader = _FrameReader(sock)
        self._packet = ServerVPNPacket()

        self.username: str = ""
        self.assigned_ip: str = ""
        self.session_id: int = -1
        self.local_port: Optional[int] = None
        self._registered = False

        self._stop = threading.Event()
        self._reasm: dict = {}
        self._send_lock = threading.Lock()
        self._announced = False
        # The 30-second ANNOUNCE_IP window starts the moment accept() returned.
        self._accept_monotonic = time.monotonic()

        # Quota (bytes), loaded on data-session registration.
        self._quota_lock = threading.Lock()
        self.current_quota: int = 0
        self._quota_enforced = False
        self._bucket: Optional[TokenBucket] = None

    # -- lifecycle --------------------------------------------------------- #
    def run(self) -> None:
        try:
            self._sock.settimeout(SOCKET_TIMEOUT)
            self.local_port = self._sock.getsockname()[1]
            first = self._reader.read_packet(self._stop.is_set)
            if first is None:
                return
            parsed = self._packet.parse(first)

            if parsed.code == CODE_REGISTER_REQUEST:
                self._handle_register(parsed)
                return
            if parsed.code != CODE_AUTH_REQUEST:
                self._try_send(self._packet.build_error(max(parsed.session_id, 0),
                                                        "Authentication required"))
                return

            # AUTH_REQUEST
            status = self._authenticate(parsed)
            if status is None:
                return  # error already sent
            self.username = parsed.username or ""

            if status == STATUS_QUOTA_EXHAUSTED:
                self._grace_window(parsed.session_id)
                return

            # Authenticated & active: decide assignment vs data by next packet.
            nxt = self._reader.read_packet(self._stop.is_set)
            if nxt is None:
                return
            parsed2 = self._packet.parse(nxt)
            if parsed2.code == CODE_GET_IP:
                self._do_assignment(parsed2.session_id)
                return
            # Otherwise this is a data socket: the FIRST packet must be a valid
            # ANNOUNCE_IP received within the announce window. The TCP source IP
            # is not trusted (add_bypass routes the control channel over the
            # physical NIC), so identity comes from the announced address.
            if not self._await_announce(parsed2):
                return
            self._recv_loop()
        except InvalidVPNPacketError:
            self._try_send(self._packet.build_error(max(self.session_id, 0),
                                                    "Malformed packet"))
        except _Stopped:
            pass
        except OSError:
            pass
        finally:
            self._cleanup()

    def stop(self) -> None:
        self._stop.set()

    # -- authentication / registration ------------------------------------ #
    def _handle_register(self, parsed) -> None:
        username = parsed.username
        password_hash = parsed.password_hash
        if not username or not password_hash:
            self._try_send(self._packet.build_error(parsed.session_id, "Missing credentials"))
            return
        if self._server.db.user_exists(username):
            self._try_send(self._packet.build_error(parsed.session_id, "Username already exists"))
            return
        created = self._server.db.create_user(username, password_hash, remaining_quota=0)
        if not created:
            self._try_send(self._packet.build_error(parsed.session_id, "Username already exists"))
            return
        self._try_send(self._packet.build_register_success(parsed.session_id))

    def _authenticate(self, parsed) -> Optional[str]:
        """Return the account_status on success, or None (error already sent)."""
        username = parsed.username
        password_hash = parsed.password_hash

        # Hardcoded admin never touches the DB and never gets a tunnel session.
        if username == ADMIN_USERNAME:
            from VPNPacket import hash_password  # local import to avoid cycle
            if password_hash == hash_password(ADMIN_USERNAME, ADMIN_PASSWORD):
                self._try_send(self._packet.build_error(parsed.session_id,
                                                        "Admin cannot open a tunnel"))
            else:
                self._try_send(self._packet.build_error(parsed.session_id, "Wrong password"))
            return None

        user = self._server.db.get_user(username or "")
        if user is None:
            self._try_send(self._packet.build_error(parsed.session_id, "User not found"))
            return None
        if user["password"] != password_hash:
            self._try_send(self._packet.build_error(parsed.session_id, "Wrong password"))
            return None
        if user["account_status"] == STATUS_BANNED:
            self._try_send(self._packet.build_error(parsed.session_id, "Account banned"))
            return None

        if user["account_status"] == STATUS_QUOTA_EXHAUSTED:
            self._try_send(self._packet.build_auth_success(parsed.session_id))
            return STATUS_QUOTA_EXHAUSTED

        if user["remaining_quota"] <= 0:
            # Active flag but no bytes left: treat as exhausted.
            self._server.db.mark_quota_exhausted(username)
            self._try_send(self._packet.build_auth_success(parsed.session_id))
            return STATUS_QUOTA_EXHAUSTED

        self._try_send(self._packet.build_auth_success(parsed.session_id))
        return STATUS_ACTIVE

    # -- quota-exhausted grace window ------------------------------------- #
    def _grace_window(self, session_id: int) -> None:
        self.session_id = session_id
        deadline = time.monotonic() + GRACE_WINDOW_SECONDS
        while not self._stop.is_set() and time.monotonic() < deadline:
            packet = self._reader.read_packet(self._stop.is_set)
            if packet is None:
                return
            try:
                parsed = self._packet.parse(packet)
            except InvalidVPNPacketError:
                continue
            if parsed.code == CODE_DISCONNECT:
                return
            if parsed.code == CODE_QUOTA_REQUEST:
                added = self._server.grant_quota(self.username, parsed.requested_bytes or 0)
                self._try_send(self._packet.build_quota_response(session_id, added))
                if added > 0:
                    # Quota restored; the client must reconnect for a real session.
                    return
            # DATA and everything else is dropped during the grace window.
        # Timed out without a successful top-up -> force disconnect.

    # -- assignment phase -------------------------------------------------- #
    def _do_assignment(self, session_id: int) -> None:
        try:
            ip = self._server.assign_ip()
        except IPPoolExhaustedError:
            self._try_send(self._packet.build_error(session_id, "No IP available"))
            return
        self._try_send(self._packet.build_assign_ip(session_id, ip))

    # -- data session ------------------------------------------------------ #
    # -- data session (ANNOUNCE_IP driven) -------------------------------- #
    def _await_announce(self, first_parsed) -> bool:
        """Require a valid ANNOUNCE_IP as the first data-socket packet.

        A 30-second window (measured from accept) applies. Any non-ANNOUNCE_IP
        packet before registration is silently dropped and does NOT reset the
        timer; a malformed/invalid/non-pending IP gets an ERROR and closes.
        Returns True once the session is registered and ready for DATA.
        """
        parsed = first_parsed
        deadline = self._accept_monotonic + ANNOUNCE_TIMEOUT_SECONDS
        # Stop reads either on shutdown or when the announce window elapses.
        announce_stop = lambda: self._stop.is_set() or time.monotonic() > deadline
        while not self._stop.is_set():
            if time.monotonic() > deadline:
                return False  # window elapsed; socket closes, IP stays reusable

            if parsed.code == CODE_ANNOUNCE_IP:
                if self._register_announced(parsed):
                    return True
                return False  # ERROR already sent (bad/non-pending IP)

            # Not an ANNOUNCE_IP yet: drop silently, keep waiting (no reset).
            try:
                nxt = self._reader.read_packet(announce_stop)
            except _Stopped:
                return False
            if nxt is None:
                return False
            try:
                parsed = self._packet.parse(nxt)
            except InvalidVPNPacketError:
                continue  # malformed pre-announce packet: drop, no timer reset
        return False

    def _register_announced(self, parsed) -> bool:
        announced_ip = parsed.ip
        session_id = parsed.session_id
        if not announced_ip or not self._server.is_pending(announced_ip):
            self._try_send(self._packet.build_error(session_id, "IP not assigned"))
            return False
        if self._server.is_active(announced_ip):
            self._try_send(self._packet.build_get_new_ip(session_id))
            return False

        self.assigned_ip = announced_ip
        self.session_id = session_id
        self._server.register_session(self)
        self._registered = True
        self._announced = True

        # Load quota into memory and set up the rate limiter.
        with self._quota_lock:
            self.current_quota = self._server.db.get_quota(self.username)
            self._quota_enforced = True
        self._bucket = TokenBucket(RATE_LIMIT_BPS, self._stop.is_set)

        if self.current_quota <= 0:
            self._quota_exhausted()
            return False
        return True

    def _recv_loop(self) -> None:
        while not self._stop.is_set():
            packet = self._reader.read_packet(self._stop.is_set)
            if packet is None:
                break
            try:
                parsed = self._packet.parse(packet)
            except InvalidVPNPacketError:
                self._try_send(self._packet.build_error(self.session_id, "Malformed packet"))
                continue
            if not self._handle_incoming(parsed):
                break

    def _handle_incoming(self, parsed) -> bool:
        code = parsed.code
        if code == CODE_DATA:
            self._handle_data(parsed)
            return not self._stop.is_set()
        if code == CODE_KEEP_ALIVE:
            return True
        if code == CODE_ANNOUNCE_IP:
            # Already registered: a repeated ANNOUNCE_IP is a protocol error.
            self._try_send(self._packet.build_error(self.session_id, "Already announced"))
            return True
        if code == CODE_DISCONNECT:
            return False
        if code == CODE_QUOTA_REQUEST:
            added = self._server.grant_quota(self.username, parsed.requested_bytes or 0)
            if added > 0:
                with self._quota_lock:
                    self.current_quota += added
            self._try_send(self._packet.build_quota_response(self.session_id, added))
            return True
        if code == CODE_STATUS:
            self._try_send(self._packet.build_status(self.session_id,
                                                     self._status_payload()))
            return True
        if code == CODE_ERROR:
            return True
        return True

    def _status_payload(self) -> bytes:
        """JSON snapshot of the account for a STATUS response (from the DB)."""
        info = self._server.get_user_info(self.username) or {}
        with self._quota_lock:
            live_quota = self.current_quota
        snapshot = {
            "username": self.username,
            "account_status": info.get("account_status"),
            "connection_status": info.get("connection_status"),
            "remaining_quota": live_quota,
            "assigned_ip": self.assigned_ip,
        }
        return json.dumps(snapshot).encode("utf-8")

    def _handle_data(self, parsed) -> None:
        buf = self._reasm.get(parsed.session_id, b"") + parsed.payload
        if parsed.mtu_flag:
            self._reasm[parsed.session_id] = buf
            return
        self._reasm.pop(parsed.session_id, None)

        # Upload counts against quota + rate limit.
        if not self._charge(len(buf)):
            return
        if self._bucket is not None:
            self._bucket.consume(len(buf))

        # Firewall + logging decision (every packet reaching here is logged).
        if not self._firewall_allows(buf):
            return

        try:
            translated = self._server.nat.translate_out(buf)
        except ValueError:
            return
        if translated is None:
            return
        # DNS sniffing on the outbound (query) side.
        self._server.dns.observe_ip_packet(buf)
        self._server.gateway.send(translated)

    def _firewall_allows(self, ip_packet: bytes) -> bool:
        """Apply firewall rules and log the decision. Returns True if forwarded."""
        try:
            pkt = IPPacket(ip_packet)
            dest_ip, dest_port = pkt.get_destination()
        except ValueError:
            return False  # unparseable: drop silently, nothing to log
        domain = self._server.resolve_domain(dest_ip)
        blocked = self._server.is_blocked(self.username, dest_ip, domain)
        action = "blocked" if blocked else "sent"
        self._server.db.log_traffic(self.username, dest_ip, dest_port, domain, action)
        return not blocked

    # -- outbound to client (called by the server's inbound dispatcher) ---- #
    def deliver(self, ip_packet: bytes) -> None:
        # Download counts against quota + rate limit.
        if not self._charge(len(ip_packet)):
            return
        if self._bucket is not None:
            self._bucket.consume(len(ip_packet))
        try:
            with self._send_lock:
                for chunk, more in _fragment(ip_packet):
                    pkt = self._packet.build_data(self.session_id, chunk, more_fragments=more)
                    _send_frame(self._sock, pkt)
        except OSError:
            self.stop()

    # -- quota accounting -------------------------------------------------- #
    def _charge(self, nbytes: int) -> bool:
        """Deduct bytes from the in-memory quota. Returns False if exhausted."""
        with self._quota_lock:
            if not self._quota_enforced:
                return True
            self.current_quota -= nbytes
            if self.current_quota <= 0:
                self.current_quota = 0
                self._quota_enforced = False
                exhausted = True
            else:
                exhausted = False
        if exhausted:
            self._quota_exhausted()
            return False
        return True

    def _quota_exhausted(self) -> None:
        if self.username:
            self._server.db.mark_quota_exhausted(self.username)
        try:
            self._try_send(self._packet.build_disconnect(self.session_id))
        except OSError:
            pass
        self.stop()

    # -- helpers ----------------------------------------------------------- #
    def _try_send(self, packet: bytes) -> None:
        try:
            with self._send_lock:
                _send_frame(self._sock, packet)
        except OSError:
            pass

    def _cleanup(self) -> None:
        if self._registered:
            # Persist remaining quota unless the account was already flagged
            # exhausted (mark_quota_exhausted already zeroed it in the DB).
            with self._quota_lock:
                final_quota = self.current_quota if self._quota_enforced else None
            self._server.unregister_session(self, final_quota)
            self._registered = False
        try:
            self._sock.close()
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# VPNServer
# --------------------------------------------------------------------------- #
class VPNServer:
    """Listens for clients, authenticates them and runs one handler per socket."""

    def __init__(
        self,
        listen_host: str = "0.0.0.0",
        listen_port: int = 443,
        exit_ip: str = "0.0.0.0",
        gateway: Optional[InternetGateway] = None,
        db_path: str = "vpn.db",
        quota_grant_policy: Optional[Callable[[str, int], int]] = None,
    ):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.exit_ip = exit_ip
        self.gateway = gateway or RawSocketGateway(exit_ip)

        # Billing hook: given (username, requested_bytes) return bytes actually
        # granted. Default grants the request; a real deployment plugs payment
        # verification in here. This is the single place quota is created.
        self._quota_grant_policy = quota_grant_policy or (lambda user, req: int(req))

        self.db = UserDB(db_path)
        self.db.reset_all_connections()  # clear stale flags from a previous crash
        self.dns = DNSCache()

        # DNS (port 53) is excluded from NAT per the design.
        self.nat = ServerNAT(exit_ip, ignored_ports=[DNS_PORT])

        net = ipaddress.ip_network(SUBNET)
        server_ip = ipaddress.ip_address(SERVER_TUNNEL_IP)
        self._free_ips: List[str] = [str(h) for h in net.hosts() if h != server_ip]
        random.shuffle(self._free_ips)

        self._pending: Set[str] = set()
        self._active_by_ip: Dict[str, ClientHandler] = {}
        self.client_map: Dict[Tuple[str, int], ClientHandler] = {}
        self._by_username: Dict[str, Set[ClientHandler]] = {}

        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._listen_sock: Optional[socket.socket] = None
        self._handlers: List[ClientHandler] = []

    # -- IP pool ----------------------------------------------------------- #
    def assign_ip(self) -> str:
        with self._lock:
            for _ in range(len(self._free_ips)):
                ip = self._free_ips.pop(0)
                if ip in self._pending or ip in self._active_by_ip:
                    self._free_ips.append(ip)
                    continue
                self._pending.add(ip)
                return ip
            raise IPPoolExhaustedError("no free IP in 10.0.0.0/24")

    def is_pending(self, ip: str) -> bool:
        with self._lock:
            return ip in self._pending

    def is_active(self, ip: str) -> bool:
        with self._lock:
            return ip in self._active_by_ip

    # -- session registry -------------------------------------------------- #
    def register_session(self, handler: ClientHandler) -> None:
        with self._lock:
            ip = handler.assigned_ip
            self._pending.discard(ip)
            self._active_by_ip[ip] = handler
            self.client_map[(ip, handler.session_id)] = handler
            self._by_username.setdefault(handler.username, set()).add(handler)
            self.nat.register_client(ip)
            if handler.local_port is not None:
                self.nat.add_ignored_port(handler.local_port)
        self.db.mark_connected(handler.username, ip)

    def unregister_session(self, handler: ClientHandler,
                           final_quota: Optional[int]) -> None:
        with self._lock:
            ip = handler.assigned_ip
            if ip:
                self._active_by_ip.pop(ip, None)
                self.client_map.pop((ip, handler.session_id), None)
                self.nat.unregister_client(ip)
                if handler.local_port is not None:
                    self.nat.remove_ignored_port(handler.local_port)
                if ip not in self._free_ips:
                    self._free_ips.append(ip)
                self._pending.discard(ip)
            group = self._by_username.get(handler.username)
            if group is not None:
                group.discard(handler)
                if not group:
                    self._by_username.pop(handler.username, None)
        if handler.username:
            # If the account was flagged exhausted, mark_quota_exhausted already
            # persisted status+quota; here we only clear the connection flag.
            self.db.mark_disconnected(handler.username, final_quota)

    # -- quota granting (billing hook) ------------------------------------ #
    def grant_quota(self, username: str, requested_bytes: int) -> int:
        """Grant quota via the configured policy and persist it. Returns granted."""
        if not username:
            return 0
        granted = max(0, int(self._quota_grant_policy(username, requested_bytes)))
        if granted > 0:
            self.db.add_quota(username, granted)
        return granted

    # -- inbound dispatch (internet -> client) ----------------------------- #
    def _on_internet_packet(self, ip_packet: bytes) -> None:
        try:
            restored = self.nat.translate_in(ip_packet)
        except ValueError:
            return
        if restored is None:
            return
        # DNS sniffing on the inbound (response) side.
        self.dns.observe_ip_packet(restored)
        try:
            dst_ip = IPPacket(restored).get_destination()[0]
        except ValueError:
            return
        with self._lock:
            handler = self._active_by_ip.get(dst_ip)
        if handler is not None:
            handler.deliver(restored)

    # -- DNS --------------------------------------------------------------- #
    def resolve_domain(self, ip: str) -> Optional[str]:
        return self.dns.resolve_domain(ip)

    # -- firewall ---------------------------------------------------------- #
    def is_blocked(self, username: str, dest_ip: str,
                   domain: Optional[str]) -> bool:
        """True if a firewall rule for this user (or 'all') blocks the target."""
        blocked_domains, blocked_ips = self.db.get_firewall_for_user(username or "")
        if dest_ip in blocked_ips:
            return True
        if domain:
            d = domain.lower()
            for rule in blocked_domains:
                # Match the exact domain or any subdomain of the rule.
                if d == rule or d.endswith("." + rule):
                    return True
        return False

    def add_firewall_domain(self, username: str, domain: str) -> int:
        return self.db.add_firewall_domain(username, domain)

    def add_firewall_ip(self, username: str, ip: str) -> int:
        return self.db.add_firewall_ip(username, ip)

    def remove_firewall_rule(self, rule_id: int, rule_type: str) -> bool:
        return self.db.remove_firewall_rule(rule_id, rule_type)

    def list_firewall_rules(self) -> Dict:
        return self.db.list_firewall_rules()

    # -- traffic logs ------------------------------------------------------ #
    def get_traffic_logs(self, username: Optional[str] = None, limit: int = 500) -> List[Dict]:
        return self.db.get_traffic_logs(username, limit)

    def clear_traffic_logs(self) -> None:
        self.db.clear_traffic_logs()

    # -- admin / panel API ------------------------------------------------- #
    def get_user_info(self, username: str) -> Optional[Dict]:
        info = self.db.get_user(username)
        if info is None:
            return None
        info.pop("password", None)  # never expose the hash to the panel layer
        with self._lock:
            info["live"] = username in self._by_username
        return info

    def list_online_users(self) -> List[Dict]:
        return self.db.list_online_users()

    def list_users(self) -> List[Dict]:
        return self.db.list_users()

    def add_quota(self, username: str, extra_bytes: int) -> int:
        """Admin: add quota to an account and push it to any live session."""
        new_total = self.db.add_quota(username, extra_bytes)
        with self._lock:
            handlers = list(self._by_username.get(username, ()))
        for h in handlers:
            with h._quota_lock:
                if h._quota_enforced:
                    h.current_quota += int(extra_bytes)
        return new_total

    def ban_user(self, username: str) -> bool:
        ok = self.db.ban_user(username)
        self.kick(username)
        return ok

    def unban_user(self, username: str) -> bool:
        return self.db.unban_user(username)

    def kick(self, username: str) -> int:
        """Force-disconnect all live sessions for a user. Returns count kicked."""
        with self._lock:
            handlers = list(self._by_username.get(username, ()))
        for h in handlers:
            h.stop()
        return len(handlers)

    def register_user(self, username: str, password_hash: str, quota: int = 0) -> bool:
        return self.db.create_user(username, password_hash, quota)

    # -- portal-facing account API (Server owns the DB) -------------------- #
    # These let the Client Portal act as a pure frontend: it authenticates and
    # requests state through the Server, which is the only DB owner. The portal
    # never imports Database or opens vpn.db.
    def portal_register(self, username: str, password: str) -> Dict:
        """Register a portal/VPN account. Returns {'ok': bool, 'error': str?}."""
        username = (username or "").strip()
        if not username or not password:
            return {"ok": False, "error": "Username and password are required"}
        if username in (ADMIN_USERNAME, ALL_USERS):
            return {"ok": False, "error": "This username is reserved"}
        ok = self.db.create_user(username, hash_password(username, password),
                                 remaining_quota=0)
        if not ok:
            return {"ok": False, "error": "Username already exists"}
        return {"ok": True}

    def portal_authenticate(self, username: str, password: str) -> Dict:
        """Validate credentials via the Server/DB. Returns status + error text."""
        username = (username or "").strip()
        if username in (ADMIN_USERNAME, ALL_USERS):
            return {"ok": False, "error": "This account cannot use the portal"}
        user = self.db.get_user(username)
        if user is None:
            return {"ok": False, "error": "User not found"}
        if user["password"] != hash_password(username, password):
            return {"ok": False, "error": "Wrong password"}
        if user["account_status"] == STATUS_BANNED:
            return {"ok": False, "error": "Account banned"}
        return {"ok": True, "account_status": user["account_status"]}

    def portal_status(self, username: str) -> Optional[Dict]:
        """Account snapshot for the portal dashboard, sourced only from the DB.

        Reflects any live in-memory quota for an active session so the value
        the user sees matches what the running tunnel is spending.
        """
        info = self.get_user_info(username)
        if info is None:
            return None
        with self._lock:
            handlers = list(self._by_username.get(username, ()))
        if handlers:
            h = handlers[0]
            with h._quota_lock:
                info["remaining_quota"] = h.current_quota
        return {
            "username": info["username"],
            "account_status": info.get("account_status"),
            "connection_status": info.get("connection_status"),
            "assigned_ip": info.get("assigned_ip"),
            "remaining_quota": info.get("remaining_quota", 0),
        }

    def portal_request_quota(self, username: str, amount: int) -> Dict:
        """Portal quota top-up. Mirrors QUOTA_REQUEST semantics via the Server."""
        try:
            amount = int(amount)
        except (TypeError, ValueError):
            return {"ok": False, "error": "Amount must be an integer number of bytes"}
        if amount <= 0:
            return {"ok": False, "error": "Amount must be a positive number of bytes"}
        if amount > 0xFFFFFFFF:
            return {"ok": False, "error": "Amount exceeds the 4294967295-byte limit"}
        if self.db.get_user(username) is None:
            return {"ok": False, "error": "User not found"}
        new_total = self.add_quota(username, amount)
        return {"ok": True, "added": amount, "remaining_quota": new_total}

    # -- server lifecycle -------------------------------------------------- #
    def start(self) -> None:
        # Raw sockets require elevation; acquire it before the gateway opens
        # them (otherwise socket() fails with WinError 10013).
        if isinstance(self.gateway, RawSocketGateway):
            ensure_admin()
        self.gateway.start(self._on_internet_packet)
        self._listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listen_sock.bind((self.listen_host, self.listen_port))
        self._listen_sock.listen(16)
        self._listen_sock.settimeout(SOCKET_TIMEOUT)
        try:
            self._accept_loop()
        finally:
            self.stop()

    def start_background(self) -> threading.Thread:
        """Start the accept loop on a daemon thread and return it."""
        t = threading.Thread(target=self.start, name="vpn-server", daemon=True)
        t.start()
        return t

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                sock, addr = self._listen_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            peer_ip = addr[0]
            handler = ClientHandler(self, sock, peer_ip)
            with self._lock:
                self._handlers.append(handler)
                self._handlers = [h for h in self._handlers if not h._stop.is_set()]
            threading.Thread(target=handler.run, name=f"client-{peer_ip}", daemon=True).start()

    def stop(self) -> None:
        if self._stop.is_set():
            return
        self._stop.set()
        with self._lock:
            handlers = list(self._handlers)
        for h in handlers:
            h.stop()
        if self._listen_sock is not None:
            try:
                self._listen_sock.close()
            except OSError:
                pass
        self.gateway.stop()


if __name__ == "__main__":
    server = VPNServer(listen_host="0.0.0.0", listen_port=8443)
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()
