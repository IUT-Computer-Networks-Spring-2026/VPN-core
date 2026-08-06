from Load_balancer_client import load_balancer_client
from Tunnel import Tunnel


class VPN_Client:
    def __init__(self):
        self.is_tunnel : bool = False
        self.is_proxy : bool = False
        self.sever_address : str = ""
        self.sever_port : int = 0
        self.get_server_info : bool = False

    def get_ip_address(self):
        load = load_balancer_client()
        server_info = load.ask()
        if server_info:
            server_ip, server_port = server_info
            self.sever_address = server_ip
            self.sever_port = server_port
            self.get_server_info = True
        else :
            raise Exception("Failed to get server IP and port from load balancer.")
            
        

    def connect_tunnel(self):
        if not self.get_server_info:
            self.get_ip_address()
        # not completed
        with Tunnel() as t:
            t.create("VPNcore",)
            self.is_tunnel = True
            while True:
                try:
                    msg = t.receive()
                    print(msg)
                except KeyboardInterrupt:
                    break
        pass

    def disconnect_tunnel(self):
        # Code to disconnect from the VPN server
        pass

    def send(self, data):
        # Code to send data through the VPN tunnel
        pass

    def receive(self):
        # Code to receive data from the VPN tunnel
        pass