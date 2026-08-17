"""Client-side VPN control/data packet builder and parser.

Wire format (4-byte header, big-endian):
    byte 0-1 : payload length (uint16)
    byte 2   : bits 7-4 code, bits 3-1 session id (0-7), bit 0 MTU flag
    byte 3   : reserved (0x00)

Self-contained (no cross-folder imports) so the Client package stays independent.
"""

import hashlib
import json
import struct
from dataclasses import dataclass
from typing import Optional


HEADER_LEN = 4
MAX_PAYLOAD = 0xFFFF
RESERVED = 0x00

# Codes
CODE_DATA = 0
CODE_KEEP_ALIVE = 1
CODE_AUTH_REQUEST = 2
CODE_AUTH_SUCCESS = 3
CODE_AUTH_FAILED = 4
CODE_QUOTA_REQUEST = 5
CODE_QUOTA_RESPONSE = 6
CODE_DISCONNECT = 7
CODE_STATUS = 8
CODE_ERROR = 9
CODE_GET_IP = 10
CODE_ASSIGN_IP = 11
CODE_GET_NEW_IP = 12
CODE_REGISTER_REQUEST = 13
CODE_REGISTER_SUCCESS = 14
CODE_ANNOUNCE_IP = 15

MAX_CODE = 15

_CODE_NAMES = {
    CODE_DATA: "DATA", CODE_KEEP_ALIVE: "KEEP_ALIVE", CODE_AUTH_REQUEST: "AUTH_REQUEST",
    CODE_AUTH_SUCCESS: "AUTH_SUCCESS", CODE_AUTH_FAILED: "AUTH_FAILED",
    CODE_QUOTA_REQUEST: "QUOTA_REQUEST", CODE_QUOTA_RESPONSE: "QUOTA_RESPONSE",
    CODE_DISCONNECT: "DISCONNECT", CODE_STATUS: "STATUS", CODE_ERROR: "ERROR",
    CODE_GET_IP: "GET_IP", CODE_ASSIGN_IP: "ASSIGN_IP", CODE_GET_NEW_IP: "GET_NEW_IP",
    CODE_REGISTER_REQUEST: "REGISTER_REQUEST", CODE_REGISTER_SUCCESS: "REGISTER_SUCCESS",
    CODE_ANNOUNCE_IP: "ANNOUNCE_IP",
}

# Codes the client is allowed to receive (server -> client direction).
_CLIENT_RECEIVABLE = frozenset({
    CODE_DATA, CODE_AUTH_SUCCESS, CODE_AUTH_FAILED, CODE_QUOTA_RESPONSE,
    CODE_DISCONNECT, CODE_STATUS, CODE_ERROR,
    CODE_ASSIGN_IP, CODE_GET_NEW_IP, CODE_REGISTER_SUCCESS,
})


class InvalidVPNPacketError(Exception):
    """Raised when a packet is malformed or not receivable in this direction."""


def hash_password(username: str, password: str) -> str:
    """SHA-256(username + password) hex digest (username acts as the salt)."""
    salted = username.encode("utf-8") + password.encode("utf-8")
    return hashlib.sha256(salted).hexdigest()


@dataclass
class ParsedPacket:
    code: int
    session_id: int
    mtu_flag: bool = False
    payload: bytes = b""
    added_bytes: Optional[int] = None     # QUOTA_RESPONSE
    status: Optional[bytes] = None        # STATUS
    ip: Optional[str] = None              # ASSIGN_IP
    error_message: Optional[str] = None   # ERROR

    @property
    def code_name(self) -> str:
        return _CODE_NAMES.get(self.code, f"UNKNOWN({self.code})")


class ClientVPNPacket:
    """Builds packets the client may send and parses packets it may receive."""

    # -- builders (client -> server) -------------------------------------- #
    def build_data(self, session_id: int, payload: bytes, more_fragments: bool = False) -> bytes:
        return _build_packet(CODE_DATA, session_id, payload, more_fragments)

    def build_keep_alive(self, session_id: int) -> bytes:
        return _build_packet(CODE_KEEP_ALIVE, session_id, b"", False)

    def build_auth_request(self, session_id: int, username: str, password: str) -> bytes:
        return _build_packet(
            CODE_AUTH_REQUEST, session_id, _credentials_payload(username, password), False
        )

    def build_register_request(self, session_id: int, username: str, password: str) -> bytes:
        return _build_packet(
            CODE_REGISTER_REQUEST, session_id, _credentials_payload(username, password), False
        )

    def build_quota_request(self, session_id: int, requested_bytes: int) -> bytes:
        if not 0 <= requested_bytes <= 0xFFFFFFFF:
            raise ValueError("requested_bytes out of uint32 range")
        return _build_packet(CODE_QUOTA_REQUEST, session_id, struct.pack("!I", requested_bytes), False)

    def build_disconnect(self, session_id: int) -> bytes:
        return _build_packet(CODE_DISCONNECT, session_id, b"", False)

    def build_status_request(self, session_id: int) -> bytes:
        return _build_packet(CODE_STATUS, session_id, b"", False)

    def build_error(self, session_id: int, message: str = "") -> bytes:
        return _build_packet(CODE_ERROR, session_id, (message or "").encode("utf-8"), False)

    def build_get_ip(self, session_id: int) -> bytes:
        return _build_packet(CODE_GET_IP, session_id, b"", False)

    def build_announce_ip(self, session_id: int, ip: str) -> bytes:
        if not isinstance(ip, str) or not ip:
            raise ValueError("ip must be a non-empty string")
        return _build_packet(CODE_ANNOUNCE_IP, session_id, ip.encode("utf-8"), False)

    # -- parser (server -> client) ---------------------------------------- #
    def parse(self, data: bytes) -> ParsedPacket:
        code, session_id, mtu_flag, payload = _parse_header_and_payload(data)

        if code not in _CLIENT_RECEIVABLE:
            raise InvalidVPNPacketError(
                f"Client cannot receive code {code} ({_CODE_NAMES.get(code, '?')})"
            )

        pkt = ParsedPacket(code=code, session_id=session_id, mtu_flag=mtu_flag, payload=payload)

        if code == CODE_QUOTA_RESPONSE:
            if len(payload) != 4:
                raise InvalidVPNPacketError("QUOTA_RESPONSE payload must be exactly 4 bytes")
            pkt.added_bytes = struct.unpack("!I", payload)[0]
        elif code == CODE_STATUS:
            pkt.status = payload
        elif code == CODE_ASSIGN_IP:
            try:
                pkt.ip = payload.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise InvalidVPNPacketError("ASSIGN_IP payload is not valid UTF-8") from exc
            if not pkt.ip:
                raise InvalidVPNPacketError("ASSIGN_IP payload must contain an IP string")
        elif code == CODE_ERROR:
            try:
                pkt.error_message = payload.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise InvalidVPNPacketError("ERROR payload is not valid UTF-8") from exc
        elif code in (CODE_AUTH_SUCCESS, CODE_AUTH_FAILED, CODE_DISCONNECT,
                      CODE_GET_NEW_IP, CODE_REGISTER_SUCCESS):
            if payload:
                raise InvalidVPNPacketError(f"{_CODE_NAMES[code]} must have no payload")
        return pkt


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #
def _credentials_payload(username: str, password: str) -> bytes:
    return json.dumps(
        {"username": username, "password": hash_password(username, password)},
        separators=(",", ":"),
    ).encode("utf-8")


def _build_packet(code: int, session_id: int, payload: bytes, mtu_flag: bool) -> bytes:
    if not 0 <= code <= MAX_CODE:
        raise ValueError(f"code out of range 0-{MAX_CODE}: {code}")
    if not 0 <= session_id <= 7:
        raise ValueError(f"session_id out of range 0-7: {session_id}")
    if payload is None:
        payload = b""
    if len(payload) > MAX_PAYLOAD:
        raise ValueError(f"payload exceeds {MAX_PAYLOAD} bytes: {len(payload)}")

    byte2 = (code << 4) | (session_id << 1) | (1 if mtu_flag else 0)
    header = struct.pack("!HBB", len(payload), byte2, RESERVED)
    return header + bytes(payload)


def _parse_header_and_payload(data: bytes):
    if data is None or len(data) < HEADER_LEN:
        raise InvalidVPNPacketError("packet shorter than 4-byte header")

    payload_len, byte2, reserved = struct.unpack_from("!HBB", data, 0)

    if reserved != RESERVED:
        raise InvalidVPNPacketError(f"reserved byte must be 0x00 (got {reserved:#04x})")

    code = (byte2 >> 4) & 0x0F
    session_id = (byte2 >> 1) & 0x07
    mtu_flag = bool(byte2 & 0x01)

    if code > MAX_CODE:
        raise InvalidVPNPacketError(f"unknown code {code}")

    expected_total = HEADER_LEN + payload_len
    if len(data) != expected_total:
        raise InvalidVPNPacketError(
            f"length mismatch: header says {payload_len} payload bytes "
            f"(total {expected_total}), got {len(data)}"
        )

    payload = bytes(data[HEADER_LEN:expected_total])
    return code, session_id, mtu_flag, payload
