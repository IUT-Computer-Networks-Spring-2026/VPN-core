import random

from Packet import IPPacket


class ClientNAT:
    MAX_ENTRIES = 10000          
    _MIN_PORT = 1                 
    _PORT_SPACE = 1 << 16         

    def __init__(self, exit_ip: str, ignored_ports=None):
        self._exit_ip = exit_ip
        self._ignored_ports = set(ignored_ports or ())
        self._out_to_nat: dict = {}
        self._nat_to_out: dict = {}

    
    def add_ignored_port(self, port: int) -> None:
        self._ignored_ports.add(port)

    def remove_ignored_port(self, port: int) -> None:
        self._ignored_ports.discard(port)

    
    def translate_out(self, packet: bytes):
        pkt = IPPacket(packet)
        src_ip, src_port = pkt.get_source()
        if src_port is None: # icmp cannot map                    
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
        dst_ip, dst_port = pkt.get_destination()
        if dst_port is None: # icmp cannot map 
            return None
        if dst_port in self._ignored_ports:       
            return packet

        original = self._nat_to_out.get((pkt.protocol, dst_port))
        if original is None:     
            return None

        pkt.set_destination(original)
        return pkt.to_bytes()

    def _allocate_port(self, protocol: int):
        port = random.randrange(self._MIN_PORT, self._PORT_SPACE)
        for _ in range(self._PORT_SPACE):
            if port >= self._MIN_PORT and port not in self._ignored_ports and (protocol, port) not in self._nat_to_out:
                return port
            port = (port + 1) % self._PORT_SPACE

        raise RuntimeError("NAT port space exhausted")

    # drop all mapping
    def _maybe_flush(self):
        if len(self._out_to_nat) > self.MAX_ENTRIES:
            self._out_to_nat.clear()
            self._nat_to_out.clear()
