from __future__ import annotations

import time

import config
from adapter import Adapter
from elevation import ensure_admin
from logging_setup import get_logger
from routing import RouteManager
from validator import check_os

log = get_logger("main")


def _pause(message: str) -> None:
    """Pause the flow so the current state can be inspected externally.

    Falls back to a timed sleep when no interactive console is available
    (e.g. when launched via a fresh elevated process).
    """
    log.info(message)
    try:
        input(f"\n>>> {message}\n>>> Press ENTER to continue...\n")
    except (EOFError, OSError):
        log.warning("No interactive stdin — sleeping 20s instead.")
        time.sleep(20)


def main() -> None:
    # 0) Sanity: this project is Windows-only and needs admin rights.
    check_os()
    ensure_admin()

    adapter = None
    router = RouteManager()

    try:
        # 1) Bring up / create the virtual network adapter.
        adapter = Adapter.create()
        if_index = adapter.wait_until_ready()
        adapter.enable_adapter()
        adapter.start_session()
        log.info("Adapter %r is up (IfIndex=%s)", adapter.name, if_index)

        # 2) Assign an IP address to it (IP is optional -> taken from config).
        router.assign_ip(if_index=if_index)

        # 3) Pause so the IP assignment can be verified manually.
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

        # 4) Activate tunnel mode (high-priority routing).
        router.create_tunnel(if_index=if_index)

        # 5) Let external tools inspect the redirected packets.
        _pause("Tunnel active. Inspect packets with an external tool, then continue.")

    finally:
        # 6) Clean up: remove routes + IP, then delete the adapter.
        try:
            router.revert()
        except Exception as exc:
            log.error("Error while reverting routes: %s", exc)
        if adapter is not None:
            adapter.close()
        log.info("Cleanup complete — adapter removed.")


if __name__ == "__main__":
    main()
