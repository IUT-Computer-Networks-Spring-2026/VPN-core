import json
import socket
from Crypto import Cesar

LOAD_BALANCER = {"IP" : "127.0.0.1" , "PORT" : 12004} # don't touch this line except for change in 2 client and server

class load_balancer_client():  
    def __init__ (self):
        pass

    def ask(ip = LOAD_BALANCER["IP"],port = LOAD_BALANCER["PORT"]):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((ip, port))
        for i in range(3):
            client_socket.send(Cesar.encode("GET".encode('utf-8')))
            client_socket.settimeout(5.0) 

            try:
                response = client_socket.recv(32)
                if not response:
                    client_socket.close()
                    continue
                else : 
                    break
            except socket.timeout:
                client_socket.close()
                print("Client Timeout")
                continue

        return json.loads(Cesar.decode(response).decode('utf-8'))


