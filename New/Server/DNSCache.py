"""Minimal DNS sniffer + reverse cache (ip -> domain).

The server inspects DNS traffic (UDP/TCP port 53) that flows through the tunnel
and records a mapping from answered IP addresses back to the queried domain
name. `resolve_domain(ip)` then returns the most recent domain seen for that IP.

Only enough of RFC 1035 is parsed to read the question name and A/AAAA answer
records. Anything malformed is ignored silently (best-effort sniffer).
"""

import struct
import threading
from typing import Dict, List, Optional, Tuple

DNS_PORT = 53

_TYPE_A = 1
_TYPE_AAAA = 28
_CLASS_IN = 1


class DNSCache:
    """Thread-safe ip -> domain cache populated from observed DNS responses."""

    def __init__(self, max_entries: int = 100_000):
        self._map: Dict[str, str] = {}
        self._lock = threading.Lock()
        self._max = max_entries

    def resolve_domain(self, ip: str) -> Optional[str]:
        with self._lock:
            return self._map.get(ip)

    def snapshot(self) -> Dict[str, str]:
        with self._lock:
            return dict(self._map)

    def observe_ip_packet(self, ip_packet: bytes) -> None:
        """Extract DNS payload from an IP packet (if port 53) and record answers."""
        dns_payload = _extract_dns_payload(ip_packet)
        if dns_payload is None:
            return
        self._ingest(dns_payload)

    # -- internal --------------------------------------------------------- #
    def _ingest(self, dns: bytes) -> None:
        parsed = _parse_dns_response(dns)
        if not parsed:
            return
        domain, ips = parsed
        if not domain or not ips:
            return
        with self._lock:
            if len(self._map) >= self._max:
                self._map.clear()  # simple bulk expiry
            for ip in ips:
                self._map[ip] = domain


# --------------------------------------------------------------------------- #
# IP / L4 extraction
# --------------------------------------------------------------------------- #
def _extract_dns_payload(ip_packet: bytes) -> Optional[bytes]:
    if ip_packet is None or len(ip_packet) < 20:
        return None
    if (ip_packet[0] >> 4) != 4:
        return None
    ihl = (ip_packet[0] & 0x0F) * 4
    if ihl < 20 or ihl > len(ip_packet):
        return None
    proto = ip_packet[9]

    if proto == 17:  # UDP
        if len(ip_packet) < ihl + 8:
            return None
        src_port, dst_port = struct.unpack_from("!HH", ip_packet, ihl)
        if DNS_PORT not in (src_port, dst_port):
            return None
        return bytes(ip_packet[ihl + 8:])
    if proto == 6:  # TCP
        if len(ip_packet) < ihl + 20:
            return None
        src_port, dst_port = struct.unpack_from("!HH", ip_packet, ihl)
        if DNS_PORT not in (src_port, dst_port):
            return None
        data_offset = (ip_packet[ihl + 12] >> 4) * 4
        payload = bytes(ip_packet[ihl + data_offset:])
        # TCP DNS is length-prefixed with a 2-byte length.
        if len(payload) < 2:
            return None
        return payload[2:]
    return None


# --------------------------------------------------------------------------- #
# DNS message parsing (best-effort)
# --------------------------------------------------------------------------- #
def _parse_name(data: bytes, offset: int) -> Tuple[str, int]:
    """Parse a (possibly compressed) DNS name. Returns (name, next_offset)."""
    labels: List[str] = []
    jumped = False
    next_offset = offset
    steps = 0
    while True:
        if offset >= len(data):
            break
        length = data[offset]
        steps += 1
        if steps > 128:  # guard against loops
            break
        if length == 0:
            offset += 1
            if not jumped:
                next_offset = offset
            break
        if (length & 0xC0) == 0xC0:  # pointer
            if offset + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                next_offset = offset + 2
            offset = pointer
            jumped = True
            continue
        offset += 1
        if offset + length > len(data):
            break
        labels.append(data[offset:offset + length].decode("ascii", "replace"))
        offset += length
    return ".".join(labels), next_offset


def _parse_dns_response(data: bytes) -> Optional[Tuple[str, List[str]]]:
    if len(data) < 12:
        return None
    _id, flags, qd, an, _ns, _ar = struct.unpack_from("!HHHHHH", data, 0)
    if qd < 1:
        return None
    offset = 12

    # Question section: read first question name (the queried domain).
    domain, offset = _parse_name(data, offset)
    if offset + 4 > len(data):
        return None
    offset += 4  # QTYPE + QCLASS
    # Skip any remaining questions.
    for _ in range(qd - 1):
        _n, offset = _parse_name(data, offset)
        offset += 4
        if offset > len(data):
            return None

    ips: List[str] = []
    for _ in range(an):
        if offset >= len(data):
            break
        _name, offset = _parse_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, rclass, _ttl, rdlength = struct.unpack_from("!HHIH", data, offset)
        offset += 10
        if offset + rdlength > len(data):
            break
        rdata = data[offset:offset + rdlength]
        offset += rdlength
        if rclass == _CLASS_IN and rtype == _TYPE_A and rdlength == 4:
            ips.append(".".join(str(b) for b in rdata))
        elif rclass == _CLASS_IN and rtype == _TYPE_AAAA and rdlength == 16:
            ips.append(":".join(f"{rdata[i]:02x}{rdata[i+1]:02x}" for i in range(0, 16, 2)))

    return domain, ips
