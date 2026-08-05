import random
import socket
from Config import LOAD_BALANCER
import json



class load_balancer_server():
    server_list = [("127.0.0.1",12001),("127.0.0.2",13002),("127.0.0.6",12004)]

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
            print(f"client with {client_address} connected")
            try:
                data = client_socket.recv(32)
                if not data:
                    continue
            except socket.timeout:
                print("⏰ Client Timeout")
                continue

            msg = data.decode('utf-8') 
            if msg.upper() == "GET" : 
                json_string = json.dumps(random.choice(self.server_list)) 
                client_socket.send(json_string.encode('utf-8')) 
            else : 
                print(f"wrong message: {msg}")
            client_socket.close() 
            print("connection closed")



# test
def main():
    tmp = load_balancer_server()
    try:
        tmp.listen_start()
    except KeyboardInterrupt:
        print("Server dowun.")


if __name__ == "__main__":
    main()