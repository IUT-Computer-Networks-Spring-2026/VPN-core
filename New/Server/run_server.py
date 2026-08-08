"""Launcher for the VPN Server + its HTTP API (the only DB owner).

Starts the VPNServer (which owns SQLite) on its TCP port and, in the same
process, serves the account/admin HTTP API on VPN_API_PORT. The Admin Panel and
Client Portal frontends are separate processes that proxy to this API — they
never touch the database.

Because the API runs inside the VPNServer process, admin actions (ban → kick,
add quota) and portal actions apply to live in-memory sessions immediately.

Run (needs Administrator on Windows for raw sockets):
    cd Server
    python run_server.py
Environment:
    VPN_DB        SQLite path (default vpn.db, resolved in Server/)
    VPN_API_PORT  HTTP API port (default 8090)
    VPN_TCP_PORT  VPN protocol port (default 8443)
    VPN_JWT_SECRET  signing secret for panel tokens
"""

import os
import threading

from VPNServer import VPNServer
from api import create_api_app

DB_PATH = os.environ.get("VPN_DB", "vpn.db")
API_PORT = int(os.environ.get("VPN_API_PORT", "8090"))
TCP_PORT = int(os.environ.get("VPN_TCP_PORT", "8443"))
API_HOST = os.environ.get("VPN_API_HOST", "127.0.0.1")


def main() -> None:
    server = VPNServer(listen_host="0.0.0.0", listen_port=TCP_PORT, db_path=DB_PATH)
    api = create_api_app(server)

    # Serve the HTTP API on a daemon thread so Ctrl+C stops the whole process.
    api_thread = threading.Thread(
        target=lambda: api.run(host=API_HOST, port=API_PORT,
                               debug=False, use_reloader=False),
        name="vpn-api", daemon=True)
    api_thread.start()

    try:
        server.start()  # blocks on the accept loop
    except KeyboardInterrupt:
        server.stop()


if __name__ == "__main__":
    main()
