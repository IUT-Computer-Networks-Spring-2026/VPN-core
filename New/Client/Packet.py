import socket
import struct


class IPPacket:
    # Standard
    ICMP = 1
    TCP = 6
    UDP = 17
    _PORTED = (TCP, UDP)    
    _SUPPORTED = (ICMP, TCP, UDP)

    _PROTO_NAMES = {ICMP: "ICMP", TCP: "TCP", UDP: "UDP"}

    _ICMP_ECHO_REPLY = 0
    _ICMP_ECHO_REQUEST = 8
    _ICMP_ECHO_TYPES = (_ICMP_ECHO_REPLY, _ICMP_ECHO_REQUEST)



    def __init__(self, raw: bytes):
        if raw is None or len(raw) < 20:
            raise ValueError("Not an IPv4 packet: fewer than 20 bytes")

        # copy
        self._buf = bytearray(raw)

        version = self._buf[0] >> 4
        if version != 4:
            raise ValueError(f"Only IPv4 is supported (got version {version})")

        # header length in bytes
        self._ihl = (self._buf[0] & 0x0F) * 4          
        if self._ihl < 20 or self._ihl > len(self._buf):
            raise ValueError(f"Invalid IPv4 header length: {self._ihl}")

        self._protocol = self._buf[9]
        self._l4 = self._ihl                            

        if (self._protocol in self._PORTED) and (len(self._buf) < self._l4 + 4): # min size of sgmnt
            raise ValueError("Truncated layer-4 header")

    
    @property
    def protocol(self):
        return self._protocol

    def get_source(self):
        return (self._read_ip(12), self._read_port(self._l4 + 0))

    def get_destination(self):
        return (self._read_ip(16), self._read_port(self._l4 + 2))

    def get_icmp_id(self):
        if not self._is_icmp_echo():
            return None
        return struct.unpack_from("!H", self._buf, self._l4 + 4)[0]

    def set_icmp_id(self, identifier):
        if not self._is_icmp_echo():
            return
        if not 0 <= identifier <= 0xFFFF:
            raise ValueError(f"ICMP identifier out of range 0-65535: {identifier}")
        struct.pack_into("!H", self._buf, self._l4 + 4, identifier)
        self._recalc_icmp_checksum()
        self._recalc_ip_checksum()

    def set_source(self, source: tuple):
        ip, port = source
        self._write_ip(12, ip)
        if port is not None: # for icmp
            self._write_port(self._l4 + 0, port)
        self._refresh_checksums()

    def set_destination(self, destination: tuple):
        ip, port = destination
        self._write_ip(16, ip)
        if port is not None:
            self._write_port(self._l4 + 2, port)
        self._refresh_checksums()

    def overview(self):
        decoded : str = ""
        start = self._payload_offset()
        data = bytes(self._buf[start:]) if start < len(self._buf) else b""
        if data:
            try:
                text = data.decode("utf-8")
                if text.isprintable():
                    decoded = text
            except UnicodeDecodeError:
                pass
            decoded = data.hex()
        else:
            decoded =  "<empty>"
        
        return {
            "protocol": self._PROTO_NAMES.get(self._protocol, f"OTHER({self._protocol})"),
            "source": self.get_source(),
            "destination": self.get_destination(),
            "payload": decoded,
        }



    def to_bytes(self):
        return bytes(self._buf) # fixed

    def __len__(self):
        return len(self._buf)


    def _read_ip(self, off: int):
        return socket.inet_ntoa(bytes(self._buf[off:off + 4])) # readable ip 

    def _write_ip(self, off: int, ip: str):
        try:
            packed = socket.inet_aton(ip)
        except OSError as exc:
            raise ValueError(f"Invalid IPv4 address: {ip!r}") from exc
        self._buf[off:off + 4] = packed

    def _read_port(self, off: int):
        if self._protocol not in self._PORTED:
            return None
        return struct.unpack_from("!H", self._buf, off)[0]

    def _write_port(self, off: int, port: int):
        if self._protocol not in self._PORTED:
            return
        if not 0 <= port <= 0xFFFF:
            raise ValueError(f"Port out of range 0-65535: {port}")
        struct.pack_into("!H", self._buf, off, port)

    @staticmethod
    def _checksum(data: bytes):
        if len(data) % 2:
            data = bytes(data) + b"\x00"         # padding
        total = 0
        for i in range(0, len(data), 2):
            total += (data[i] << 8) | data[i + 1]
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
        return (~total) & 0xFFFF #complement

    def _refresh_checksums(self):
        self._recalc_ip_checksum()
        if self._protocol in self._PORTED:
            self._recalc_l4_checksum()

    def _recalc_ip_checksum(self):
        self._buf[10:12] = b"\x00\x00"  # set 0
        csum = self._checksum(bytes(self._buf[0:self._ihl]))
        struct.pack_into("!H", self._buf, 10, csum)

    def _pseudo_header(self, l4_len: int):
        return (bytes(self._buf[12:16]) + bytes(self._buf[16:20]) + b"\x00" + bytes([self._protocol]) + struct.pack("!H", l4_len))

    def _recalc_l4_checksum(self) -> None:
        csum_off = self._l4 + (16 if self._protocol == self.TCP else 6)

        struct.pack_into("!H", self._buf, csum_off, 0)
        segment = bytes(self._buf[self._l4:])
        csum = self._checksum(self._pseudo_header(len(segment)) + segment)

        # UDP checksum of 0
        if self._protocol == self.UDP and csum == 0:
            csum = 0xFFFF

        struct.pack_into("!H", self._buf, csum_off, csum)

    
    def _is_icmp_echo(self):
        if self._protocol != self.ICMP or len(self._buf) < self._l4 + 8:
            return False
        return self._buf[self._l4] in self._ICMP_ECHO_TYPES

    def _recalc_icmp_checksum(self):
        csum_off = self._l4 + 2
        struct.pack_into("!H", self._buf, csum_off, 0)
        message = bytes(self._buf[self._l4:])
        struct.pack_into("!H", self._buf, csum_off, self._checksum(message))

    def _payload_offset(self):
        if self._protocol == self.TCP:
            data_offset = (self._buf[self._l4 + 12] >> 4) * 4
            return self._l4 + data_offset
        if self._protocol == self.UDP:
            return self._l4 + 8
        if self._protocol == self.ICMP:
            return self._l4 + 8                  
        return len(self._buf)                    

   
