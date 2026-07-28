from enum import Enum

import Validator

class Connection_method(Enum):
    Proxy = 1
    Tunnel = 2
    


class ClientVPN :  
    MAX_PACKET_SIZE = 1500

    def __init__(self, ip, port):
        Validator.validate_host_port(ip,port)
        self.host = ip
        self.port = port
        self.connected = False

    def connect(self):
        self.connected = True
        return f"Connected to {self.host}:{self.port}"

    def send(self, data):
        return f"Sending {len(data)} bytes"

    def __del__(self):
        pass