import hashlib
import json
import struct
from dataclasses import dataclass, field
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

_CODE_NAMES = {
    CODE_DATA: "DATA", CODE_KEEP_ALIVE: "KEEP_ALIVE", CODE_AUTH_REQUEST: "AUTH_REQUEST",
    CODE_AUTH_SUCCESS: "AUTH_SUCCESS", CODE_AUTH_FAILED: "AUTH_FAILED",
    CODE_QUOTA_REQUEST: "QUOTA_REQUEST", CODE_QUOTA_RESPONSE: "QUOTA_RESPONSE",
    CODE_DISCONNECT: "DISCONNECT", CODE_STATUS: "STATUS", CODE_ERROR: "ERROR",
}

# allowed codes
_CLIENT_RECEIVABLE = frozenset({
    CODE_DATA, CODE_AUTH_SUCCESS, CODE_AUTH_FAILED, CODE_QUOTA_RESPONSE,
    CODE_DISCONNECT, CODE_STATUS, CODE_ERROR,
})


class InvalidVPNPacketError(Exception):
    pass


@dataclass
class ParsedPacket:
    code: int
    session_id: int
    mtu_flag: bool = False
    payload: bytes = b""
    added_bytes: Optional[int] = None    
    status: Optional[bytes] = None    

    @property
    def code_name(self) :
        return _CODE_NAMES.get(self.code, f"UNKNOWN({self.code})")


class ClientVPNPacket:

    def build_data(self, session_id: int, payload: bytes, more_fragments: bool = False):
        return self._build(CODE_DATA, session_id, payload, mtu_flag=more_fragments)

    def build_keep_alive(self, session_id: int):
        return self._build(CODE_KEEP_ALIVE, session_id, b"")

    def build_auth_request(self, session_id: int, username: str, password: str):
        salted = username.encode("utf-8") + password.encode("utf-8")
        password_hash = hashlib.sha256(salted).hexdigest()
        payload = json.dumps(
            {"username": username, "password": password_hash},
            separators=(",", ":"),
        ).encode("utf-8")
        return self._build(CODE_AUTH_REQUEST, session_id, payload)

    def build_quota_request(self, session_id: int, requested_bytes: int):
        if not 0 <= requested_bytes <= 0xFFFFFFFF:
            raise ValueError("requested_bytes out of uint32 range")
        return self._build(CODE_QUOTA_REQUEST, session_id, struct.pack("!I", requested_bytes))

    def build_disconnect(self, session_id: int):
        return self._build(CODE_DISCONNECT, session_id, b"")

    def build_status_request(self, session_id: int):
        return self._build(CODE_STATUS, session_id, b"")

    def build_error(self, session_id: int) -> bytes:
        return self._build(CODE_ERROR, session_id, b"")

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
        elif code in (CODE_AUTH_SUCCESS, CODE_AUTH_FAILED, CODE_DISCONNECT, CODE_ERROR):
            if payload:
                raise InvalidVPNPacketError(f"{_CODE_NAMES[code]} must have no payload")
        return pkt

    
    @staticmethod
    def _build(code: int, session_id: int, payload: bytes, mtu_flag: bool = False):
        return _build_packet(code, session_id, payload, mtu_flag)



def _build_packet(code: int, session_id: int, payload: bytes, mtu_flag: bool):
    if not 0 <= code <= 9:
        raise ValueError(f"code out of range 0-9: {code}")
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

    if code > 9:
        raise InvalidVPNPacketError(f"unknown code {code}")

    expected_total = HEADER_LEN + payload_len
    if len(data) != expected_total:
        raise InvalidVPNPacketError(
            f"length mismatch: header says {payload_len} payload bytes "
            f"(total {expected_total}), got {len(data)}"
        )

    payload = bytes(data[HEADER_LEN:expected_total])
    return code, session_id, mtu_flag, payload
