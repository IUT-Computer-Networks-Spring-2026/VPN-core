import json
from Config import LOAD_BALANCER
import socket


class load_balancer_server():  
    def __init__ (self):
        pass

    def ask(ip = LOAD_BALANCER["IP"],port = LOAD_BALANCER["PORT"]):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((LOAD_BALANCER["IP"],LOAD_BALANCER["PORT"]))
        for i in range(3):
            client_socket.send("GET".encode('utf-8'))
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
                print("⏰ Client Timeout")
                continue

        return json.loads(response.decode('utf-8'))



# test 
def main():
    load = load_balancer_server()
    server_info = load.ask()
    if server_info:
        print(f"server ip & port : {server_info}")
    else :
        print(";(")

if __name__ == "__main__":
    main()