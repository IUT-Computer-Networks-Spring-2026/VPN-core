"""
Terminal packet monitor for VPN-core.

Prints a continuous, human-readable stream of packets that hit the virtual
adapter. Can be used in two ways:

1. **Standalone** (recommended for watching traffic live)::

       python packet_monitor.py

   This elevates, brings up the adapter + high-priority routes, and prints
   every captured packet to the console until you press Ctrl+C.

2. **As a handler module** inside your own code::

       from packet_monitor import TerminalPacketMonitor
       from packet_pipeline import CompositePacketHandler, LoggingPacketHandler

       monitor = TerminalPacketMonitor()
       handler = CompositePacketHandler(monitor, MyVpnHandler())
       pipeline = PacketPipeline(adapter, handler)

WARNING
-------
While the high-priority routes are installed, *all* IPv4 traffic is steered
into the virtual adapter. The monitor only *observes* packets — it does not
forward them. Your machine will lose normal Internet connectivity until you
stop the program (routes are cleaned up on exit). Use a short test window
or implement a real VPN forwarder in ``handle_outbound``.
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime
from typing import Optional, TextIO

from packet_pipeline import Action, HandlerResult, PacketHandler, summarize_packet
from logging_setup import get_logger, setup_logging

log = get_logger("monitor")


class TerminalPacketMonitor(PacketHandler):
    """
    PacketHandler that pretty-prints every outbound packet to a stream
    (stdout by default) and then drops it.

    Compose with your real handler via :class:`CompositePacketHandler` if you
    also want to forward traffic.
    """

    def __init__(
        self,
        stream: Optional[TextIO] = None,
        *,
        show_hex: bool = False,
        hex_bytes: int = 32,
        color: bool = True,
    ) -> None:
        self.stream = stream or sys.stdout
        self.show_hex = show_hex
        self.hex_bytes = hex_bytes
        self.color = color and hasattr(self.stream, "isatty") and self.stream.isatty()
        self.count = 0
        self.bytes_total = 0
        self._start: Optional[float] = None

    # -- PacketHandler ------------------------------------------------------

    def on_start(self) -> None:
        self._start = time.time()
        self._write(self._banner("VPN-core packet monitor started — Ctrl+C to stop"))

    def on_stop(self) -> None:
        elapsed = (time.time() - self._start) if self._start else 0.0
        self._write(
            self._banner(
                f"monitor stopped — packets={self.count} bytes={self.bytes_total} "
                f"elapsed={elapsed:.1f}s"
            )
        )

    def handle_outbound(self, packet: bytes) -> HandlerResult:
        self.count += 1
        self.bytes_total += len(packet)
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        summary = summarize_packet(packet)
        line = f"[{ts}] #{self.count:<6} {summary}"
        if self.color:
            line = f"\033[36m{line}\033[0m"
        self._write(line)

        if self.show_hex and packet:
            dumped = packet[: self.hex_bytes].hex(" ")
            more = " ..." if len(packet) > self.hex_bytes else ""
            self._write(f"         hex: {dumped}{more}")

        # Observe only — do not inject or forward.
        return HandlerResult(Action.DROP)

    def handle_inbound(self, packet: bytes) -> HandlerResult:
        # Still print replies if the pipeline calls us on the inbound path.
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        summary = summarize_packet(packet)
        line = f"[{ts}] IN      {summary}"
        if self.color:
            line = f"\033[33m{line}\033[0m"
        self._write(line)
        return HandlerResult(Action.INJECT_TO_OS, data=packet)

    # -- helpers ------------------------------------------------------------

    def _write(self, text: str) -> None:
        try:
            self.stream.write(text + "\n")
            self.stream.flush()
        except Exception:
            pass

    @staticmethod
    def _banner(msg: str) -> str:
        bar = "=" * 72
        return f"{bar}\n{msg}\n{bar}"


# ---------------------------------------------------------------------------
# Standalone entry point
# ---------------------------------------------------------------------------

def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Live terminal monitor for packets hitting the VPN-core Wintun adapter.",
    )
    parser.add_argument(
        "--hex",
        action="store_true",
        help="Also print a short hex dump of each packet.",
    )
    parser.add_argument(
        "--hex-bytes",
        type=int,
        default=32,
        help="How many bytes to include in the hex dump (default: 32).",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colours.",
    )
    parser.add_argument(
        "--log-level",
        default="WARNING",
        help="Logging level for non-monitor messages (default: WARNING).",
    )
    parser.add_argument(
        "--protect-host",
        action="append",
        default=[],
        metavar="IP",
        help="IPv4 host that must keep using the real gateway (repeatable). "
             "Use this for your VPN server address to avoid routing loops.",
    )
    args = parser.parse_args(argv)

    setup_logging(level=args.log_level)

    # Local imports so --help works even if wintun.dll is missing.
    from elevation import ensure_admin
    from main import VpnCore

    ensure_admin()

    monitor = TerminalPacketMonitor(
        show_hex=args.hex,
        hex_bytes=args.hex_bytes,
        color=not args.no_color,
    )

    core = VpnCore(
        handler=monitor,
        protect_hosts=args.protect_host,
    )

    print("Starting VPN-core in monitor mode...")
    print("All IPv4 traffic will be redirected to the virtual adapter.")
    print("Packets are displayed but NOT forwarded — connectivity will pause.")
    print("Press Ctrl+C to stop and restore routes.\n")

    try:
        core.start()
        while core.is_running:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nCtrl+C received.")
    finally:
        core.stop()

    return 0


if __name__ == "__main__":
    sys.exit(main())
