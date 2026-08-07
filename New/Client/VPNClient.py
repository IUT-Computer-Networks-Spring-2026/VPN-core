from Load_balancer_client import load_balancer_client
from Tunnel import Tunnel


# instruction list
# Client : GET_IP_ADDRESS





class VPN_Client:
    def __init__(self):
        self.is_tunnel : bool = False
        self.is_proxy : bool = False
        self.sever_address : str = ""
        self.sever_port : int = 0
        

    def get_server_info(self):
        load = load_balancer_client()
        server_info = load.ask()
        if server_info:
            server_ip, server_port = server_info
            self.sever_address = server_ip
            self.sever_port = server_port
        else :
            raise Exception("Failed to get server IP and port from load balancer.")
            
        

    def connect_tunnel(self):
        if not self.sever_address or not self.sever_port:
            self.get_server_info()
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

    