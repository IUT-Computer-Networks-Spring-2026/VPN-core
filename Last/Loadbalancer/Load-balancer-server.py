import random
import socket
import json
from Crypto import Cesar

LOAD_BALANCER = {"IP" : "127.0.0.1" , "PORT" : 12004} # don't touch this line except for change in 2 client and server

class load_balancer_server():
    server_list = [("172.20.41.161",9000)]

    def __init__(self):
        pass

    def listen_start(self):
        listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
        listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listen_socket.bind((LOAD_BALANCER["IP"],LOAD_BALANCER["PORT"])) 
        listen_socket.listen(5) 
        while True:
            client_socket, client_address = listen_socket.accept() 
            client_socket.settimeout(5.0) 
            try:
                data = client_socket.recv(32)
                if not data:
                    continue
            except socket.timeout:
                continue

            msg = Cesar.decode(data).decode('utf-8') 
            if msg.upper() == "GET" : 
                json_string = json.dumps(random.choice(self.server_list)) 
                client_socket.send(Cesar.encode(json_string.encode('utf-8'))) 
            else : 
                pass
            client_socket.close() 



# test
def main():
    tmp = load_balancer_server()
    try:
        tmp.listen_start()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()