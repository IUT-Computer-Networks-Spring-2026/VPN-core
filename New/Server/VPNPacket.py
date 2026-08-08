"""Server-side VPN control/data packet builder and parser.

Wire format (4-byte header, big-endian):
    byte 0-1 : payload length (uint16)
    byte 2   : bits 7-4 code, bits 3-1 session id (0-7), bit 0 MTU flag
    byte 3   : reserved (0x00)

This module is intentionally self-contained (no cross-folder imports) so the
Server package can be deployed independently of the Client package.
"""

import json
import struct
import hashlib
from dataclasses import dataclass
from typing import Optional


def hash_password(username: str, password: str) -> str:
    """SHA-256(username + password) hex digest (username acts as the salt)."""
    salted = username.encode("utf-8") + password.encode("utf-8")
    return hashlib.sha256(salted).hexdigest()


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

# Codes the server is allowed to receive (client -> server direction).
_SERVER_RECEIVABLE = frozenset({
    CODE_DATA, CODE_KEEP_ALIVE, CODE_AUTH_REQUEST, CODE_QUOTA_REQUEST,
    CODE_DISCONNECT, CODE_STATUS, CODE_ERROR, CODE_GET_IP, CODE_REGISTER_REQUEST,
    CODE_ANNOUNCE_IP,
})


class InvalidVPNPacketError(Exception):
    """Raised when a packet is malformed or not receivable in this direction."""


@dataclass
class ParsedPacket:
    code: int
    session_id: int
    mtu_flag: bool = False
    payload: bytes = b""
    username: Optional[str] = None          # AUTH_REQUEST / REGISTER_REQUEST
    password_hash: Optional[str] = None     # AUTH_REQUEST / REGISTER_REQUEST
    requested_bytes: Optional[int] = None   # QUOTA_REQUEST
    error_message: Optional[str] = None     # ERROR
    ip: Optional[str] = None                # ANNOUNCE_IP

    @property
    def code_name(self) -> str:
        return _CODE_NAMES.get(self.code, f"UNKNOWN({self.code})")


class ServerVPNPacket:
    """Builds packets the server may send and parses packets it may receive."""

    # -- builders (server -> client) -------------------------------------- #
    def build_data(self, session_id: int, payload: bytes, more_fragments: bool = False) -> bytes:
        return _build_packet(CODE_DATA, session_id, payload, more_fragments)

    def build_auth_success(self, session_id: int) -> bytes:
        return _build_packet(CODE_AUTH_SUCCESS, session_id, b"", False)

    def build_auth_failed(self, session_id: int) -> bytes:
        return _build_packet(CODE_AUTH_FAILED, session_id, b"", False)

    def build_quota_response(self, session_id: int, added_bytes: int) -> bytes:
        if not 0 <= added_bytes <= 0xFFFFFFFF:
            raise ValueError("added_bytes out of uint32 range")
        return _build_packet(CODE_QUOTA_RESPONSE, session_id, struct.pack("!I", added_bytes), False)

    def build_disconnect(self, session_id: int) -> bytes:
        return _build_packet(CODE_DISCONNECT, session_id, b"", False)

    def build_status(self, session_id: int, status: bytes = b"") -> bytes:
        return _build_packet(CODE_STATUS, session_id, status, False)

    def build_error(self, session_id: int, message: str = "") -> bytes:
        payload = (message or "").encode("utf-8")
        return _build_packet(CODE_ERROR, session_id, payload, False)

    def build_assign_ip(self, session_id: int, ip: str) -> bytes:
        if not isinstance(ip, str) or not ip:
            raise ValueError("ip must be a non-empty string")
        return _build_packet(CODE_ASSIGN_IP, session_id, ip.encode("utf-8"), False)

    def build_get_new_ip(self, session_id: int) -> bytes:
        return _build_packet(CODE_GET_NEW_IP, session_id, b"", False)

    def build_register_success(self, session_id: int) -> bytes:
        return _build_packet(CODE_REGISTER_SUCCESS, session_id, b"", False)

    # -- parser (client -> server) ---------------------------------------- #
    def parse(self, data: bytes) -> ParsedPacket:
        code, session_id, mtu_flag, payload = _parse_header_and_payload(data)

        if code not in _SERVER_RECEIVABLE:
            raise InvalidVPNPacketError(
                f"Server cannot receive code {code} ({_CODE_NAMES.get(code, '?')})"
            )

        pkt = ParsedPacket(code=code, session_id=session_id, mtu_flag=mtu_flag, payload=payload)

        if code in (CODE_AUTH_REQUEST, CODE_REGISTER_REQUEST):
            pkt.username, pkt.password_hash = _decode_credentials(payload)
        elif code == CODE_QUOTA_REQUEST:
            if len(payload) != 4:
                raise InvalidVPNPacketError("QUOTA_REQUEST payload must be exactly 4 bytes")
            pkt.requested_bytes = struct.unpack("!I", payload)[0]
        elif code == CODE_ERROR:
            pkt.error_message = _decode_text(payload)
        elif code == CODE_ANNOUNCE_IP:
            pkt.ip = _decode_text(payload)
            if not pkt.ip:
                raise InvalidVPNPacketError("ANNOUNCE_IP payload must contain an IP string")
        elif code in (CODE_KEEP_ALIVE, CODE_DISCONNECT, CODE_GET_IP):
            if payload:
                raise InvalidVPNPacketError(f"{_CODE_NAMES[code]} must have no payload")
        return pkt


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #
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


def _decode_credentials(payload: bytes):
    try:
        obj = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidVPNPacketError(f"credential payload is not valid JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise InvalidVPNPacketError("credential JSON must be an object")
    username = obj.get("username")
    password_hash = obj.get("password")
    if not isinstance(username, str) or not isinstance(password_hash, str):
        raise InvalidVPNPacketError("credentials must contain string 'username' and 'password'")
    return username, password_hash


def _decode_text(payload: bytes) -> str:
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InvalidVPNPacketError("ERROR payload is not valid UTF-8") from exc
