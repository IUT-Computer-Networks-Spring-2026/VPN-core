import random

from Packet import IPPacket


class ClientNAT:
    MAX_ENTRIES = 10000
    MAX_ICMP_ENTRIES = 50
    _MIN_PORT = 1
    _PORT_SPACE = 1 << 16
    _ID_SPACE = 1 << 16      

    def __init__(self, exit_ip: str, ignored_ports=None):
        self._exit_ip = exit_ip
        self._ignored_ports = set(ignored_ports or ())

        
        self._out_to_nat: dict = {}
        self._nat_to_out: dict = {}

        
        self._icmp_out_to_nat: dict = {}
        self._icmp_nat_to_out: dict = {}

    def add_ignored_port(self, port: int) -> None:
        self._ignored_ports.add(port)

    def remove_ignored_port(self, port: int) -> None:
        self._ignored_ports.discard(port)

    def translate_out(self, packet: bytes):
        pkt = IPPacket(packet)

        if pkt.protocol == IPPacket.ICMP:
            return self._icmp_out(pkt)

        src_ip, src_port = pkt.get_source()
        if src_port is None: # wihtout port will drop          
            return None

        flow = (pkt.protocol, src_ip, src_port)
        nat_port = self._out_to_nat.get(flow)
        if nat_port is None:
            nat_port = self._allocate_port(pkt.protocol)
            self._out_to_nat[flow] = nat_port
            self._nat_to_out[(pkt.protocol, nat_port)] = (src_ip, src_port)
            self._maybe_flush()

        pkt.set_source((self._exit_ip, nat_port))
        return pkt.to_bytes()

    def translate_in(self, packet: bytes):
        pkt = IPPacket(packet)

        if pkt.protocol == IPPacket.ICMP:
            return self._icmp_in(pkt)

        dst_ip, dst_port = pkt.get_destination()
        if dst_port is None:
            return None
        if dst_port in self._ignored_ports:
            return packet

        original = self._nat_to_out.get((pkt.protocol, dst_port))
        if original is None:# no mapping
            return None

        pkt.set_destination(original)
        return pkt.to_bytes()


    def _icmp_out(self, pkt: IPPacket):
        original_id = pkt.get_icmp_id()
        if original_id is None:
            return None

        src_ip, _ = pkt.get_source()
        flow = (src_ip, original_id)
        nat_id = self._icmp_out_to_nat.get(flow)

        if nat_id is None:
            if len(self._icmp_out_to_nat) >= self.MAX_ICMP_ENTRIES: # clear previous mapping
                self._icmp_nat_to_out.clear()
                self._icmp_out_to_nat.clear()
            nat_id = self._allocate_icmp_id()
            self._icmp_out_to_nat[flow] = nat_id
            self._icmp_nat_to_out[nat_id] = flow

        pkt.set_source((self._exit_ip, None))  
        pkt.set_icmp_id(nat_id) # rewrite identifier
        return pkt.to_bytes()

    def _icmp_in(self, pkt: IPPacket):
        nat_id = pkt.get_icmp_id()
        if nat_id is None: # cannot map
            return None

        original = self._icmp_nat_to_out.get(nat_id)
        if original is None: #drop
            return None

        src_ip, original_id = original
        # restoring
        pkt.set_destination((src_ip, None))  
        pkt.set_icmp_id(original_id)
        return pkt.to_bytes()

    def _allocate_port(self, protocol: int):
        port = random.randrange(self._MIN_PORT, self._PORT_SPACE)
        for _ in range(self._PORT_SPACE):
            if port >= self._MIN_PORT and port not in self._ignored_ports and (protocol, port) not in self._nat_to_out:
                return port
            port = (port + 1) % self._PORT_SPACE

        raise RuntimeError("NAT port space exhausted")

    def _allocate_icmp_id(self):
        candidate = random.randrange(0, self._ID_SPACE)
        for _ in range(self._ID_SPACE):
            if candidate not in self._icmp_nat_to_out:
                return candidate
            candidate = (candidate + 1) % self._ID_SPACE

        raise RuntimeError("ICMP identifier space exhausted")

    # ---- cleanup -----------------------------------------------------------
    def _maybe_flush(self):
        if len(self._out_to_nat) > self.MAX_ENTRIES:
            self._out_to_nat.clear()
            self._nat_to_out.clear()
