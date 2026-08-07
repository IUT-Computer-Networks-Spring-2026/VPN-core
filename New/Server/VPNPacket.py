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

MAX_CODE = 12


_CODE_NAMES = {
    CODE_DATA: "DATA", CODE_KEEP_ALIVE: "KEEP_ALIVE", CODE_AUTH_REQUEST: "AUTH_REQUEST",
    CODE_AUTH_SUCCESS: "AUTH_SUCCESS", CODE_AUTH_FAILED: "AUTH_FAILED",
    CODE_QUOTA_REQUEST: "QUOTA_REQUEST", CODE_QUOTA_RESPONSE: "QUOTA_RESPONSE",
    CODE_DISCONNECT: "DISCONNECT", CODE_STATUS: "STATUS", CODE_ERROR: "ERROR",
    CODE_GET_IP: "GET_IP", CODE_ASSIGN_IP: "ASSIGN_IP", CODE_GET_NEW_IP: "GET_NEW_IP",
}

# allowed to recv
_SERVER_RECEIVABLE = frozenset({
    CODE_DATA, CODE_KEEP_ALIVE, CODE_AUTH_REQUEST, CODE_QUOTA_REQUEST,
    CODE_DISCONNECT, CODE_STATUS, CODE_ERROR,
    CODE_GET_IP,
})


class InvalidVPNPacketError(Exception):
    pass


@dataclass
class ParsedPacket:
    code: int
    session_id: int
    mtu_flag: bool = False
    payload: bytes = b""
    username: Optional[str] = None          # AUTH_REQUEST
    password_hash: Optional[str] = None     # AUTH_REQUEST
    requested_bytes: Optional[int] = None   # QUOTA_REQUEST

    @property
    def code_name(self) -> str:
        return _CODE_NAMES.get(self.code, f"UNKNOWN({self.code})")


class ServerVPNPacket:
    def build_data(self, session_id: int, payload: bytes, more_fragments: bool = False):
        return _build_packet(CODE_DATA, session_id, payload, more_fragments)

    def build_auth_success(self, session_id: int):
        return _build_packet(CODE_AUTH_SUCCESS, session_id, b"", False)

    def build_auth_failed(self, session_id: int):
        return _build_packet(CODE_AUTH_FAILED, session_id, b"", False)

    def build_quota_response(self, session_id: int, added_bytes: int):
        if not 0 <= added_bytes <= 0xFFFFFFFF:
            raise ValueError("added_bytes out of uint32 range")
        return _build_packet(CODE_QUOTA_RESPONSE, session_id, struct.pack("!I", added_bytes), False)

    def build_disconnect(self, session_id: int) -> bytes:
        return _build_packet(CODE_DISCONNECT, session_id, b"", False)

    def build_status(self, session_id: int, status: bytes = b""):
        return _build_packet(CODE_STATUS, session_id, status, False)

    def build_error(self, session_id: int) -> bytes:
        return _build_packet(CODE_ERROR, session_id, b"", False)

    def build_assign_ip(self, session_id: int, ip: str):
        if not isinstance(ip, str) or not ip:
            raise ValueError("ip must be a non-empty string")
        return _build_packet(CODE_ASSIGN_IP, session_id, ip.encode("utf-8"), False)

    def build_get_new_ip(self, session_id: int):
        return _build_packet(CODE_GET_NEW_IP, session_id, b"", False)

    def parse(self, data: bytes) -> ParsedPacket:
        code, session_id, mtu_flag, payload = _parse_header_and_payload(data)

        if code not in _SERVER_RECEIVABLE:
            raise InvalidVPNPacketError(
                f"Server cannot receive code {code} ({_CODE_NAMES.get(code, '?')})"
            )

        pkt = ParsedPacket(code=code, session_id=session_id, mtu_flag=mtu_flag, payload=payload)

        if code == CODE_AUTH_REQUEST:
            username, password_hash = _decode_auth_request(payload)
            pkt.username = username
            pkt.password_hash = password_hash
        elif code == CODE_QUOTA_REQUEST:
            if len(payload) != 4:
                raise InvalidVPNPacketError("QUOTA_REQUEST payload must be exactly 4 bytes")
            pkt.requested_bytes = struct.unpack("!I", payload)[0]
        elif code in (CODE_KEEP_ALIVE, CODE_DISCONNECT, CODE_ERROR, CODE_GET_IP):
            if payload:
                raise InvalidVPNPacketError(f"{_CODE_NAMES[code]} must have no payload")
        return pkt


def _build_packet(code: int, session_id: int, payload: bytes, mtu_flag: bool):
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


def _decode_auth_request(payload: bytes):
    try:
        obj = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidVPNPacketError(f"AUTH_REQUEST payload is not valid JSON: {exc}") from exc

    if not isinstance(obj, dict):
        raise InvalidVPNPacketError("AUTH_REQUEST JSON must be an object")
    username = obj.get("username")
    password_hash = obj.get("password")
    if not isinstance(username, str) or not isinstance(password_hash, str):
        raise InvalidVPNPacketError("AUTH_REQUEST must contain string 'username' and 'password'")
    return username, password_hash
