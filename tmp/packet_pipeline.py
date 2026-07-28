"""
Packet processing pipeline for the Wintun virtual adapter.

Architecture
============

Windows routes outbound IPv4 traffic into the Wintun adapter (via the
high-priority routes installed by :mod:`routing`). Those packets appear
here as raw L3 buffers (IPv4 or IPv6 headers at offset 0 — no Ethernet
header).

Flow::

    OS  --(route)-->  Wintun adapter  --(ReceivePacket)-->  PacketPipeline
                                                                  |
                                                          your PacketHandler
                                                                  |
                     +---------------------+----------------------+
                     |                     |                      |
                   DROP              FORWARD_REMOTE          INJECT_TO_OS
                     |                     |                      |
                    (log)         UDP/TCP to VPN peer    WintunSendPacket
                                                          (reply path)

How to hook your own logic
==========================

1. Subclass :class:`PacketHandler` (or implement the same methods).
2. Override :meth:`PacketHandler.handle_outbound` for packets the OS sent
   into the tunnel (the common case when capturing "all traffic").
3. Optionally override :meth:`PacketHandler.handle_inbound` if you have a
   separate receive thread that pulls data from a VPN peer and wants a
   single place to inspect replies before they are injected into the OS.
4. Pass your handler to :class:`PacketPipeline`.

Minimal example::

    from packet_pipeline import PacketHandler, HandlerResult, Action

    class MyFilter(PacketHandler):
        def handle_outbound(self, packet: bytes) -> HandlerResult:
            # Inspect / modify the IP packet here.
            if packet and (packet[0] >> 4) == 4:   # IPv4
                proto = packet[9]
                # ... your logic ...
            # Typical VPN path (you implement encrypt + send):
            #   self.vpn_socket.sendall(encrypt(packet))
            return HandlerResult(Action.DROP)      # already forwarded manually

            # Or ask the pipeline to inject a crafted reply into the OS:
            # return HandlerResult(Action.INJECT_TO_OS, data=reply_packet)

    pipeline = PacketPipeline(adapter, MyFilter())
    pipeline.start()

Important notes
===============

* Wintun is **L3 only**. You will never see Ethernet frames.
* "Forward to the real default gateway" from userspace is **not** the same
  as calling ``WintunSendPacket``. Sending a packet back into Wintun
  delivers it to the local OS network stack as an *inbound* packet — it
  does **not** transmit it out the physical NIC.
* A real VPN does this::

      outbound OS packet  ->  encrypt  ->  UDP send to VPN server
      UDP recv from server ->  decrypt  ->  WintunSendPacket (into OS)

* Transparent local re-injection onto a physical interface requires an
  additional driver such as WinDivert. That is intentionally out of
  scope here; the hooks above are the integration points.
"""

from __future__ import annotations

import logging
import struct
import threading
import time
from abc import ABC
from dataclasses import dataclass
from enum import Enum, auto
from typing import Callable, Optional

import config
from adapter import Adapter
from logging_setup import get_logger

log = get_logger("pipeline")


# ---------------------------------------------------------------------------
# Handler API
# ---------------------------------------------------------------------------

class Action(Enum):
    """What the pipeline should do with a packet after your handler returns."""

    DROP = auto()
    """Discard the packet (handler already dealt with it, or filter drop)."""

    INJECT_TO_OS = auto()
    """
    Inject ``HandlerResult.data`` into the Wintun adapter so the local OS
    receives it as an inbound IP packet. Typically used for VPN replies.
    """


@dataclass
class HandlerResult:
    action: Action = Action.DROP
    data: Optional[bytes] = None  # required when action is INJECT_TO_OS


class PacketHandler(ABC):
    """
    Base class for packet processing logic.

    Override the methods you need. Default implementations drop everything
    after logging at DEBUG level.
    """

    def handle_outbound(self, packet: bytes) -> HandlerResult:
        """
        Called for every packet received from the Wintun session
        (i.e. traffic the OS routed into the virtual adapter).

        Return a :class:`HandlerResult` describing the next step.
        """
        log.debug("Default handler dropping outbound packet (%s bytes)", len(packet))
        return HandlerResult(Action.DROP)

    def handle_inbound(self, packet: bytes) -> HandlerResult:
        """
        Optional hook for packets that arrived from a remote peer and are
        about to be injected into the OS. Default: inject unchanged.
        """
        return HandlerResult(Action.INJECT_TO_OS, data=packet)

    def on_start(self) -> None:
        """Called once when the pipeline starts."""

    def on_stop(self) -> None:
        """Called once when the pipeline stops."""


class CallbackPacketHandler(PacketHandler):
    """
    Convenience handler that delegates to callables.

    Example::

        def my_logic(packet: bytes) -> HandlerResult:
            print(packet[:20].hex())
            return HandlerResult(Action.DROP)

        handler = CallbackPacketHandler(on_outbound=my_logic)
    """

    def __init__(
        self,
        on_outbound: Optional[Callable[[bytes], HandlerResult]] = None,
        on_inbound: Optional[Callable[[bytes], HandlerResult]] = None,
    ) -> None:
        self._on_outbound = on_outbound
        self._on_inbound = on_inbound

    def handle_outbound(self, packet: bytes) -> HandlerResult:
        if self._on_outbound:
            return self._on_outbound(packet)
        return super().handle_outbound(packet)

    def handle_inbound(self, packet: bytes) -> HandlerResult:
        if self._on_inbound:
            return self._on_inbound(packet)
        return super().handle_inbound(packet)


class LoggingPacketHandler(PacketHandler):
    """
    Logs a one-line summary of every outbound packet, then drops it.

    Safe default while you develop your real handler. Does **not** forward
    traffic, so applications will hang if all traffic is routed into the
    tunnel — use only for capture/inspection tests, or compose with a real
    forwarder.
    """

    def __init__(self, log_level: int = logging.INFO) -> None:
        self._level = log_level
        self.packets_seen = 0

    def handle_outbound(self, packet: bytes) -> HandlerResult:
        self.packets_seen += 1
        summary = summarize_packet(packet)
        log.log(self._level, "OUT #%s %s", self.packets_seen, summary)
        return HandlerResult(Action.DROP)


class CompositePacketHandler(PacketHandler):
    """
    Fan-out to multiple handlers.

    Each handler is invoked in order. The **last** non-DROP result wins for
    injection decisions; side-effect-only handlers should return DROP.
    """

    def __init__(self, *handlers: PacketHandler) -> None:
        self.handlers = list(handlers)

    def on_start(self) -> None:
        for h in self.handlers:
            h.on_start()

    def on_stop(self) -> None:
        for h in reversed(self.handlers):
            h.on_stop()

    def handle_outbound(self, packet: bytes) -> HandlerResult:
        result = HandlerResult(Action.DROP)
        for h in self.handlers:
            r = h.handle_outbound(packet)
            if r.action != Action.DROP:
                result = r
        return result

    def handle_inbound(self, packet: bytes) -> HandlerResult:
        result = HandlerResult(Action.INJECT_TO_OS, data=packet)
        for h in self.handlers:
            r = h.handle_inbound(packet)
            if r.action != Action.DROP:
                result = r
            else:
                return r
        return result


# ---------------------------------------------------------------------------
# Packet summarisation helpers (shared with the monitor)
# ---------------------------------------------------------------------------

_IP_PROTO = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
}


def _ipv4_addr(b: bytes) -> str:
    return ".".join(str(x) for x in b)


def summarize_packet(packet: bytes) -> str:
    """Return a short human-readable summary of an L3 packet."""
    if not packet:
        return "empty"

    version = packet[0] >> 4
    length = len(packet)

    if version == 4:
        if length < 20:
            return f"IPv4 truncated ({length} B)"
        ihl = (packet[0] & 0x0F) * 4
        total_len = struct.unpack("!H", packet[2:4])[0]
        proto = packet[9]
        src = _ipv4_addr(packet[12:16])
        dst = _ipv4_addr(packet[16:20])
        proto_name = _IP_PROTO.get(proto, str(proto))
        extra = ""
        if proto in (6, 17) and length >= ihl + 4:
            sport, dport = struct.unpack("!HH", packet[ihl : ihl + 4])
            extra = f" {sport}->{dport}"
        return f"IPv4 {src} -> {dst} {proto_name}{extra} len={total_len}/{length}"

    if version == 6:
        if length < 40:
            return f"IPv6 truncated ({length} B)"
        payload_len = struct.unpack("!H", packet[4:6])[0]
        next_hdr = packet[6]
        src = _ipv6_addr(packet[8:24])
        dst = _ipv6_addr(packet[24:40])
        proto_name = _IP_PROTO.get(next_hdr, str(next_hdr))
        return f"IPv6 {src} -> {dst} {proto_name} payload={payload_len} len={length}"

    return f"unknown version={version} len={length} head={packet[:8].hex()}"


def _ipv6_addr(b: bytes) -> str:
    # Compact-ish presentation; good enough for a monitor line.
    parts = [f"{b[i]<<8 | b[i+1]:x}" for i in range(0, 16, 2)]
    return ":".join(parts)


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

class PacketPipeline:
    """
    Background receive loop bound to an :class:`Adapter` session.

    Usage::

        pipeline = PacketPipeline(adapter, handler)
        pipeline.start()
        ...
        pipeline.stop()
    """

    def __init__(
        self,
        adapter: Adapter,
        handler: Optional[PacketHandler] = None,
        *,
        receive_wait_ms: Optional[int] = None,
    ) -> None:
        self.adapter = adapter
        self.handler = handler or LoggingPacketHandler()
        self.receive_wait_ms = (
            receive_wait_ms if receive_wait_ms is not None else config.RECEIVE_WAIT_MS
        )

        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.stats = {
            "received": 0,
            "dropped": 0,
            "injected": 0,
            "errors": 0,
        }

    # -- lifecycle ----------------------------------------------------------

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            log.warning("Pipeline already running")
            return
        if not self.adapter.session_active:
            raise RuntimeError("Adapter session is not started")

        self._stop.clear()
        self.handler.on_start()
        self._thread = threading.Thread(
            target=self._run,
            name="wintun-rx",
            daemon=True,
        )
        self._thread.start()
        log.info("Packet pipeline started")

    def stop(self, timeout: float = 5.0) -> None:
        log.info("Stopping packet pipeline...")
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
            if self._thread.is_alive():
                log.warning("Pipeline thread did not exit within %.1fs", timeout)
        try:
            self.handler.on_stop()
        except Exception as exc:
            log.error("handler.on_stop() raised: %s", exc)
        log.info(
            "Pipeline stopped — received=%s dropped=%s injected=%s errors=%s",
            self.stats["received"],
            self.stats["dropped"],
            self.stats["injected"],
            self.stats["errors"],
        )

    def inject_inbound(self, packet: bytes) -> bool:
        """
        Run *packet* through ``handle_inbound`` and, if accepted, inject it
        into the OS via Wintun. Call this from your VPN peer receive path.
        """
        try:
            result = self.handler.handle_inbound(packet)
        except Exception as exc:
            self.stats["errors"] += 1
            log.exception("handle_inbound failed: %s", exc)
            return False

        if result.action == Action.INJECT_TO_OS and result.data:
            ok = self.adapter.send_packet(result.data)
            if ok:
                self.stats["injected"] += 1
            return ok

        self.stats["dropped"] += 1
        return False

    # -- context manager ----------------------------------------------------

    def __enter__(self) -> "PacketPipeline":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()

    # -- internal -----------------------------------------------------------

    def _run(self) -> None:
        log.debug("Receive loop entered")
        while not self._stop.is_set():
            try:
                packet = self.adapter.receive_packet(timeout_ms=self.receive_wait_ms)
            except RuntimeError as exc:
                # Session terminating — exit cleanly.
                log.warning("Receive loop ending: %s", exc)
                break
            except Exception as exc:
                self.stats["errors"] += 1
                log.exception("Receive error: %s", exc)
                time.sleep(0.05)
                continue

            if packet is None:
                continue

            self.stats["received"] += 1
            self._dispatch_outbound(packet)

        log.debug("Receive loop exited")

    def _dispatch_outbound(self, packet: bytes) -> None:
        try:
            result = self.handler.handle_outbound(packet)
        except Exception as exc:
            self.stats["errors"] += 1
            log.exception("handle_outbound failed: %s", exc)
            return

        if result.action == Action.INJECT_TO_OS:
            data = result.data if result.data is not None else packet
            try:
                if self.adapter.send_packet(data):
                    self.stats["injected"] += 1
                else:
                    self.stats["dropped"] += 1
            except Exception as exc:
                self.stats["errors"] += 1
                log.exception("send_packet failed: %s", exc)
        else:
            self.stats["dropped"] += 1
