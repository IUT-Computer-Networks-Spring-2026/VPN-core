import os
import threading

from VPNServer import VPNServer
from api import create_api_app

DB_PATH = os.environ.get("VPN_DB", "vpn.db")
TCP_PORT = int(os.environ.get("VPN_TCP_PORT", "9000"))
API_HOST = os.environ.get("VPN_API_HOST", "0.0.0.0")


def main() -> None:
    server = VPNServer(listen_host="0.0.0.0", listen_port=TCP_PORT, db_path=DB_PATH)
    api = create_api_app(server)

    
    api_thread = threading.Thread(
        target=lambda: api.run(host=API_HOST, port=TCP_PORT+1,
                               debug=False, use_reloader=False),
        name="vpn-api", daemon=True)
    api_thread.start()

    try:
        server.start()  
    except KeyboardInterrupt:
        server.stop()


if __name__ == "__main__":
    main()
