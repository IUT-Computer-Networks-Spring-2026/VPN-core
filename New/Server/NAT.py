import random
from collections import OrderedDict

from Packet import IPPacket


class ServerNAT:
    MAX_L4_PER_CLIENT = 200       
    MAX_ICMP_PER_CLIENT = 10      
    _MIN_PORT = 1                 
    _PORT_SPACE = 1 << 16         
    _ID_SPACE = 1 << 16           

    def __init__(self, exit_ip: str, ignored_ports=None):
        self._exit_ip = exit_ip
        self._ignored_ports = set(ignored_ports or ())

        self._clients: set = set()
        self._l4_fwd: dict = {}
        self._l4_rev: dict = {}

        self._icmp_fwd: dict = {}
        self._icmp_rev: dict = {}

    def register_client(self, client_ip: str):
        if client_ip not in self._clients:
            self._clients.add(client_ip)
            self._l4_fwd[client_ip] = OrderedDict()
            self._icmp_fwd[client_ip] = OrderedDict()

    def unregister_client(self, client_ip: str):
        if client_ip not in self._clients:
            return
        for (proto, _src_port), nat_port in self._l4_fwd[client_ip].items():
            self._l4_rev.pop((proto, nat_port), None)
        for _original_id, nat_id in self._icmp_fwd[client_ip].items():
            self._icmp_rev.pop(nat_id, None)
        del self._l4_fwd[client_ip]
        del self._icmp_fwd[client_ip]
        self._clients.discard(client_ip)

    def is_client(self, client_ip: str) -> bool:
        return client_ip in self._clients

    def add_ignored_port(self, port: int) -> None:
        self._ignored_ports.add(port)

    def remove_ignored_port(self, port: int) -> None:
        self._ignored_ports.discard(port)

    def translate_out(self, packet: bytes):
        pkt = IPPacket(packet)
        src_ip, _ = pkt.get_source()
        if src_ip not in self._clients: # unknown client
            return None

        if pkt.protocol == IPPacket.ICMP:
            return self._icmp_out(pkt, src_ip)

        _, src_port = pkt.get_source()
        if src_port is None:
            return None

        table = self._l4_fwd[src_ip]
        flow = (pkt.protocol, src_port)
        nat_port = table.get(flow)

        if nat_port is None:
            if len(table) >= self.MAX_L4_PER_CLIENT:
                self._evict_l4_lru(src_ip)
            nat_port = self._allocate_port(pkt.protocol)
            table[flow] = nat_port
            self._l4_rev[(pkt.protocol, nat_port)] = (src_ip, src_port)
        else:
            table.move_to_end(flow) # for LRU

        pkt.set_source((self._exit_ip, nat_port))
        return pkt.to_bytes()

    def translate_in(self, packet: bytes):
        pkt = IPPacket(packet)

        if pkt.protocol == IPPacket.ICMP:
            return self._icmp_in(pkt)

        _, dst_port = pkt.get_destination()
        if dst_port is None:                    
            return None
        if dst_port in self._ignored_ports:
            return packet

        original = self._l4_rev.get((pkt.protocol, dst_port))
        if original is None: # no mapping
            return None

        client_ip, src_port = original
        table = self._l4_fwd.get(client_ip)
        if table is not None:
            flow = (pkt.protocol, src_port)
            if flow in table:
                table.move_to_end(flow)  # LRU

        pkt.set_destination((client_ip, src_port))
        return pkt.to_bytes()

    
    def _icmp_out(self, pkt: IPPacket, src_ip: str):
        original_id = pkt.get_icmp_id()
        if original_id is None: #no mapping
            return None

        table = self._icmp_fwd[src_ip]
        nat_id = table.get(original_id)

        if nat_id is None:
            if len(table) >= self.MAX_ICMP_PER_CLIENT:
                self._evict_icmp_lru(src_ip)
            nat_id = self._allocate_icmp_id()
            table[original_id] = nat_id
            self._icmp_rev[nat_id] = (src_ip, original_id)
        else:
            table.move_to_end(original_id)

        pkt.set_source((self._exit_ip, None))      
        pkt.set_icmp_id(nat_id)
        return pkt.to_bytes()

    def _icmp_in(self, pkt: IPPacket):
        nat_id = pkt.get_icmp_id()
        if nat_id is None:                        
            return None

        original = self._icmp_rev.get(nat_id)
        if original is None:                       
            return None

        client_ip, original_id = original
        table = self._icmp_fwd.get(client_ip)
        if table is not None and original_id in table:
            table.move_to_end(original_id)

        pkt.set_destination((client_ip, None))     
        pkt.set_icmp_id(original_id)
        return pkt.to_bytes()


    def _evict_l4_lru(self, client_ip: str) -> None:
        (proto, _src_port), nat_port = self._l4_fwd[client_ip].popitem(last=False)
        self._l4_rev.pop((proto, nat_port), None)

    def _evict_icmp_lru(self, client_ip: str) -> None:
        _original_id, nat_id = self._icmp_fwd[client_ip].popitem(last=False)
        self._icmp_rev.pop(nat_id, None)

    def _allocate_port(self, protocol: int) -> int:
        port = random.randrange(self._MIN_PORT, self._PORT_SPACE)
        for _ in range(self._PORT_SPACE):
            if port >= self._MIN_PORT and port not in self._ignored_ports and (protocol, port) not in self._l4_rev:
                return port
            port = (port + 1) % self._PORT_SPACE
        raise RuntimeError("NAT port space exhausted")

    def _allocate_icmp_id(self) -> int:
        candidate = random.randrange(0, self._ID_SPACE)
        for _ in range(self._ID_SPACE):
            if candidate not in self._icmp_rev:
                return candidate
            candidate = (candidate + 1) % self._ID_SPACE
        raise RuntimeError("ICMP identifier space exhausted")
