
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



class VPNClientError(Exception):
    pass


class ConnectionSetupError(VPNClientError):
    pass


class ReconnectExhaustedError(VPNClientError):
    pass


class ServerError(VPNClientError):
    pass


class AuthError(VPNClientError):
    pass



class _Stopped(Exception):
    pass

class _FrameReader:


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



class VPNClient:
    

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


    def register(self) -> None:
        
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
        # self.server_ip, self.server_port = self._lb_ask()
        print("\n[DEBUG] 1. connect() called.")
        # self.server_ip, self.server_port = self._lb_ask()
        self.server_ip = "172.20.41.161"
        self.server_port = 9000
        print(f"[DEBUG] 2. Target server set to: {self.server_ip}:{self.server_port}")
        
        self._retries_left = MAX_RETRIES
        self._establish()

    def request_quota(self, requested_bytes: int) -> None:
        if self._sock is None:
            raise VPNClientError("Not connected")
        _send_frame(self._sock, self._packet.build_quota_request(self.session_id, requested_bytes))

    def disconnect(self) -> None:
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


    def _establish(self) -> None:
        print("[DEBUG] 3. _establish() started.")
        last_error: Optional[Exception] = None
        while self._retries_left > 0:
            print(f"\n[DEBUG] 4. Connection attempt. Retries left: {self._retries_left}")
            self._retries_left -= 1
            try:
                print("[DEBUG] 5. Calling _handshake_get_ip()...")
                assigned_ip = self._handshake_get_ip()
                print(f"[DEBUG] 13. _handshake_get_ip() success. Assigned IP: {assigned_ip}")
            except _NeedNewIP:
                print("[DEBUG] Catch: _NeedNewIP exception. Retrying...")
                continue
            except AuthError as exc:
                print(f"[DEBUG] Catch: AuthError: {exc}")
                raise  
            except (OSError, InvalidVPNPacketError, ServerError) as exc:
                print(f"[DEBUG] Catch: Transient error during handshake: {exc}")
                last_error = exc
                continue
            
            print("[DEBUG] 14. Proceeding to bring up tunnel and open data connection...")
            try:
                self._bring_up_tunnel(assigned_ip)
                print("[DEBUG] 15. Tunnel brought up successfully.")
                self._open_data_connection()
                print("[DEBUG] 16. Data connection opened.")
                self._reset_state()
                self._start_threads()
                print("[DEBUG] 17. _establish() completed successfully. Client is fully connected.")
                return
            except AuthError as exc:
                print(f"[DEBUG] Catch: AuthError during data connection: {exc}")
                self._close_socket()
                self._close_tunnel()
                raise
            except Exception as exc:
                print(f"[DEBUG] Catch: Exception during tunnel/data setup: {exc}")
                last_error = exc
                self._close_socket()
                self._close_tunnel()

        print("[DEBUG] Exhausted all retries.")
        if last_error is not None:
            raise ReconnectExhaustedError(
                f"Could not establish VPN session after {MAX_RETRIES} attempts: {last_error}"
            )
        raise ReconnectExhaustedError(
            f"Server kept requesting a new IP; gave up after {MAX_RETRIES} attempts"
        )

    def _authenticate(self, sock: socket.socket, reader: _FrameReader) -> None:
        print("[DEBUG] 9. _authenticate() started. Sending AUTH_REQUEST...")
        _send_frame(sock, self._packet.build_auth_request(
            self.session_id, self.username, self.password))
        
        print("[DEBUG] 10. AUTH_REQUEST sent. Waiting for response...")
        packet = reader.read_packet(lambda: False)
        
        if packet is None:
            print("[DEBUG] Auth Error: Server closed connection during authentication (packet is None).")
            raise ConnectionSetupError("Server closed connection during authentication")
            
        parsed = self._packet.parse(packet)
        print(f"[DEBUG] Received response for AUTH_REQUEST. Code: {parsed.code_name}")
        
        if parsed.code == CODE_AUTH_SUCCESS:
            print("[DEBUG] Authentication successful!")
            return
        if parsed.code == CODE_AUTH_FAILED:
            print("[DEBUG] Auth Error: Authentication failed (CODE_AUTH_FAILED).")
            raise AuthError("Authentication failed")
        if parsed.code == CODE_ERROR:
            print(f"[DEBUG] Auth Error: Authentication rejected with ERROR: {parsed.error_message}")
            raise AuthError(parsed.error_message or "Authentication rejected")
            
        print(f"[DEBUG] Unexpected auth response: {parsed.code_name}")
        raise ConnectionSetupError(f"Unexpected auth response {parsed.code_name}")
    
    def _handshake_get_ip(self) -> str:
        print("[DEBUG] 6. _handshake_get_ip() started.")
        self.session_id = random.randint(0, 7)
        print(f"[DEBUG] 7. Generated session ID: {self.session_id}, creating handshake socket...")
        temp = socket.create_connection((self.server_ip, self.server_port), timeout=10)
        try:
            temp.settimeout(10)
            reader = _FrameReader(temp)
            print("[DEBUG] 8. Socket created. Calling _authenticate()...")
            self._authenticate(temp, reader)

            print("[DEBUG] 11. Sending GET_IP request...")
            _send_frame(temp, self._packet.build_get_ip(self.session_id))
            print("[DEBUG] 12. GET_IP sent. Waiting for response...")
            packet = reader.read_packet(lambda: False)
            
            if packet is None:
                print("[DEBUG] Handshake Error: Server closed connection waiting for GET_IP response.")
                raise ConnectionSetupError("Server closed connection during handshake")
            
            parsed = self._packet.parse(packet)
            print(f"[DEBUG] Received response for GET_IP. Code: {parsed.code_name}")

            if parsed.code == CODE_ASSIGN_IP:
                if not parsed.ip:
                    print("[DEBUG] Handshake Error: ASSIGN_IP missing IP address.")
                    raise ConnectionSetupError("ASSIGN_IP without an address")
                return parsed.ip
            if parsed.code == CODE_GET_NEW_IP:
                print("[DEBUG] Server requested CODE_GET_NEW_IP.")
                raise _NeedNewIP()
            if parsed.code == CODE_ERROR:
                print(f"[DEBUG] Handshake ERROR from server: {parsed.error_message}")
                raise ServerError(parsed.error_message or "Server returned ERROR during handshake")
            
            print(f"[DEBUG] Unexpected handshake response: {parsed.code_name}")
            raise ConnectionSetupError(f"Unexpected handshake response {parsed.code_name}")
        finally:
            print("[DEBUG] Closing handshake socket.")
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

        self._authenticate(self._sock, self._reader)
        self._nat = ClientNAT(self.assigned_ip, ignored_ports=[self._local_port])
        _send_frame(self._sock, self._packet.build_announce_ip(self.session_id, self.assigned_ip))

    def _reset_state(self) -> None:
        self._stop_event.clear()
        self._reconnect_requested.clear()
        self._reasm.clear()
        with self._lock:
            self._last_activity = time.time()


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
    pass


def _default_tunnel_factory():
    from Tunnel import Tunnel  
    return Tunnel()


def _default_lb_ask() -> Tuple[str, int]:
    result = load_balancer_client.ask()
    return str(result[0]), int(result[1])


if __name__ == "__main__":
    print("Salam ahvalin")
    import sys
    if len(sys.argv) < 3:
        sys.exit("usage: VPNClient.py <username> <password>")
    client = VPNClient(sys.argv[1], sys.argv[2])
    print(f"gala boo user : {sys.argv[1]} boo ramzidan : {sys.argv[2]}")
    try:
        print("isiram vasl olom")
        client.connect()
        client.wait()
    except KeyboardInterrupt:
        pass
    finally:
        client.disconnect()
