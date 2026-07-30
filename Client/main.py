from __future__ import annotations

import time

import config
from adapter import Adapter
from elevation import ensure_admin
from logger import get_logger
from routing import RouteManager
from validator import check_os

log = get_logger("main")


def _pause(message: str) -> None:
    log.info(message)
    try:
        input(f"\n>>> {message}\n>>> Press ENTER to continue...\n")
    except (EOFError, OSError):
        log.warning("No interactive stdin — sleeping 20s instead.")
        time.sleep(20)


def main() -> None:
    check_os()
    ensure_admin()

    adapter = None
    router = RouteManager()

    try:
        adapter = Adapter.create()
        _pause("Adapter created")
        if_index = adapter.wait_until_ready()
        _pause("Adapter is ready")
        adapter.enable_adapter()
        _pause("Adapter enabled")
        adapter.start_session()
        _pause("Session started. assigning ip...")
        log.info("Adapter %r is up (IfIndex=%s)", adapter.name, if_index)

        router.assign_ip(if_index=if_index)
        _pause("ip assigned")
        
        if router.has_ip(if_index=if_index):
            log.info(
                "Verified: %s is assigned to %r. "
                "Check externally with: Get-NetIPAddress -InterfaceIndex %s",
                router.ip_address,
                adapter.name,
                if_index,
            )
        else:
            log.error("has_ip() reports no IP on the adapter — assignment failed.")

        _pause("IP assigned. Verify it, then continue to activate tunnel mode.")

        router.create_tunnel(if_index=if_index)

        
        _pause("Tunnel active. Inspect packets with an external tool, then continue.")

    finally:
        try:
            router.revert()
        except Exception as exc:
            log.error("Error while reverting routes: %s", exc)
        if adapter is not None:
            adapter.close()
        log.info("Cleanup complete — adapter removed.")


if __name__ == "__main__":
    main()
