from __future__ import annotations

__all__ = [
    "VpnCore",
    "Adapter",
    "RouteManager",
    "PacketPipeline",
    "PacketHandler",
    "ensure_admin",
]

try:
    from main import VpnCore
    from adapter import Adapter
    from routing import RouteManager
    from elevation import ensure_admin
except ImportError:
    pass
