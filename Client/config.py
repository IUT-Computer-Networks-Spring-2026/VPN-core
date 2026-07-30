from __future__ import annotations

import os
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

# Directory that contains this package / wintun.dll (not necessarily CWD).
PACKAGE_DIR: Path = Path(__file__).resolve().parent

# Prefer an explicit env override, otherwise look next to this file.
WINTUN_DLL_PATH: str = os.environ.get(
    "WINTUN_DLL_PATH",
    str(PACKAGE_DIR / "wintun.dll"),
)

# Optional log file. Set to None to disable file logging.
LOG_FILE: str | None = os.environ.get("VPNCORE_LOG_FILE", str(PACKAGE_DIR / "vpncore.log"))

# ---------------------------------------------------------------------------
# Wintun adapter
# ---------------------------------------------------------------------------

# Friendly name shown in `Get-NetAdapter` / ncpa.cpl.
ADAPTER_NAME: str = "VPNCore"

# Tunnel type string registered with the driver (usually "Wintun").
TUNNEL_TYPE: str = "Wintun"

# Ring buffer capacity for the Wintun session.
# Must be a power of two in [0x20000, 0x4000000] (128 KiB .. 64 MiB).
SESSION_CAPACITY: int = 0x400000  # 4 MiB

# ---------------------------------------------------------------------------
# Virtual interface addressing
# ---------------------------------------------------------------------------
# The OS will send packets destined for the Internet into this interface
# once high-priority routes are installed. Userspace then receives those
# packets from the Wintun session.

# IP assigned to the virtual adapter.
ADAPTER_IP: str = "10.8.0.2"

# Prefix length for ADAPTER_IP (e.g. 24 => 255.255.255.0).
ADAPTER_PREFIX_LENGTH: int = 24

# Next-hop used in routes that point at the virtual adapter.
# Must be on-link with ADAPTER_IP (same subnet). It does not need to
# answer ARP; Wintun is L3-only and the OS will still enqueue packets.
VIRTUAL_GATEWAY: str = "10.8.0.1"

# Interface metric for the virtual adapter (lower = higher priority).
INTERFACE_METRIC: int = 1

# Route metric for the high-priority default routes (lower = preferred).
ROUTE_METRIC: int = 1

# Split-default destinations (WireGuard-style). These are more specific
# than 0.0.0.0/0, so they win over the existing default gateway without
# deleting it.
HIGH_PRIORITY_PREFIXES: tuple[str, ...] = (
    "0.0.0.0/1",
    "128.0.0.0/1",
)

# ---------------------------------------------------------------------------
# Runtime behaviour
# ---------------------------------------------------------------------------

# How long (ms) the receive loop waits on the Wintun read event before
# checking the stop flag again.
RECEIVE_WAIT_MS: int = 500

# How many times / how long to wait for the adapter to show up in Windows
# after WintunCreateAdapter.
ADAPTER_READY_ATTEMPTS: int = 40
ADAPTER_READY_DELAY_SEC: float = 0.25

# Logging
LOG_LEVEL: str = os.environ.get("VPNCORE_LOG_LEVEL", "INFO")
LOG_TO_CONSOLE: bool = True

# ---------------------------------------------------------------------------
# Remote VPN server (placeholder / hypothetical for now)
# ---------------------------------------------------------------------------
# The client forwards traffic to this endpoint over TCP. The IP is a
# configurable placeholder; point it at the real server when available.
SERVER_IP: str = os.environ.get("VPNCORE_SERVER_IP", "127.0.0.1")
SERVER_PORT: int = int(os.environ.get("VPNCORE_SERVER_PORT", "9000"))

# Seconds to wait when establishing the TCP connection to the server.
SERVER_CONNECT_TIMEOUT: float = float(os.environ.get("VPNCORE_SERVER_TIMEOUT", "10"))

# ---------------------------------------------------------------------------
# Proxy mode
# ---------------------------------------------------------------------------
# Local listener for proxy mode. Bound to loopback so only local apps can
# reach it; every accepted connection is relayed to (SERVER_IP, SERVER_PORT).
PROXY_LISTEN_HOST: str = os.environ.get("VPNCORE_PROXY_HOST", "127.0.0.1")
PROXY_LISTEN_PORT: int = int(os.environ.get("VPNCORE_PROXY_PORT", "2018"))

# Backlog for the proxy listener socket.
PROXY_BACKLOG: int = 128

# ---------------------------------------------------------------------------
# Socket / forwarding
# ---------------------------------------------------------------------------
# Chunk size used when relaying bytes between sockets / the adapter.
SOCKET_BUFFER_SIZE: int = 65535
