"""
IP assignment and high-priority routing via PowerShell.

After the Wintun adapter exists, this module:

  1. Discovers the OS default gateway (so we can protect / restore it).
  2. Assigns a static IPv4 address to the virtual adapter.
  3. Sets a low interface metric (high priority).
  4. Installs WireGuard-style split default routes (0.0.0.0/1 + 128.0.0.0/1)
     so **all** IPv4 traffic is steered into the virtual adapter without
     deleting the real default route.
  5. Tears everything back down cleanly on exit.

PowerShell is used only for NetTCPIP cmdlets (robust on modern Windows).
Every invocation is checked for non-zero exit codes and non-empty stderr.
"""

from __future__ import annotations

import json
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import config
from logging_setup import get_logger

log = get_logger("routing")


# ---------------------------------------------------------------------------
# PowerShell helper
# ---------------------------------------------------------------------------

class PowerShellError(RuntimeError):
    """Raised when a PowerShell command fails."""

    def __init__(self, command: str, returncode: int, stdout: str, stderr: str) -> None:
        self.command = command
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        super().__init__(
            f"PowerShell failed (exit {returncode}): {stderr.strip() or stdout.strip() or 'unknown error'}"
        )


def _ps(command: str, *, check: bool = True, timeout: int = 60) -> str:
    """
    Run a PowerShell command and return stdout.

    Uses -NoProfile / -ExecutionPolicy Bypass for a clean, predictable host.
    """
    log.debug("PS> %s", command)
    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command,
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
        encoding="utf-8",
        errors="replace",
    )

    if result.stdout:
        log.debug("PS stdout: %s", result.stdout.rstrip())
    if result.stderr:
        # PowerShell sometimes writes progress / warnings to stderr even on success.
        level = log.warning if result.returncode != 0 else log.debug
        level("PS stderr: %s", result.stderr.rstrip())

    if check and result.returncode != 0:
        raise PowerShellError(command, result.returncode, result.stdout, result.stderr)

    return result.stdout.strip()


def _quote(value: str) -> str:
    """Escape a string for inclusion inside single-quoted PowerShell literals."""
    return value.replace("'", "''")


def _ps_json(command: str) -> Any:
    """Run a command that emits JSON and parse it."""
    raw = _ps(command)
    if not raw:
        return None
    return json.loads(raw)


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

@dataclass
class DefaultGatewayInfo:
    """Description of the OS default IPv4 route before we touch anything."""

    if_index: int
    next_hop: str
    interface_alias: str = ""
    route_metric: int = 0
    interface_metric: int = 0


def get_default_gateway() -> Optional[DefaultGatewayInfo]:
    """
    Return the current best default IPv4 gateway, or None if none exists.
    """
    script = r"""
$route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Sort-Object RouteMetric, InterfaceMetric |
    Select-Object -First 1
if (-not $route) { return }
$alias = (Get-NetAdapter -InterfaceIndex $route.InterfaceIndex -ErrorAction SilentlyContinue).Name
$ifMetric = (Get-NetIPInterface -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).InterfaceMetric
[pscustomobject]@{
    if_index = $route.InterfaceIndex
    next_hop = $route.NextHop
    interface_alias = $alias
    route_metric = $route.RouteMetric
    interface_metric = $ifMetric
} | ConvertTo-Json -Compress
"""
    data = _ps_json(script)
    if not data:
        log.warning("No default IPv4 gateway found on this system.")
        return None

    info = DefaultGatewayInfo(
        if_index=int(data["if_index"]),
        next_hop=str(data["next_hop"]),
        interface_alias=str(data.get("interface_alias") or ""),
        route_metric=int(data.get("route_metric") or 0),
        interface_metric=int(data.get("interface_metric") or 0),
    )
    log.info(
        "Real default gateway: next_hop=%s ifIndex=%s alias=%r metric=%s/%s",
        info.next_hop,
        info.if_index,
        info.interface_alias,
        info.route_metric,
        info.interface_metric,
    )
    return info


def get_ifindex_by_name(adapter_name: str) -> int:
    """Resolve a NetAdapter name to IfIndex."""
    name = _quote(adapter_name)
    out = _ps(
        f"(Get-NetAdapter -Name '{name}' -ErrorAction Stop | "
        f"Select-Object -ExpandProperty ifIndex)"
    )
    return int(out.strip())


def wait_for_adapter_name(
    adapter_name: str,
    attempts: Optional[int] = None,
    delay: Optional[float] = None,
) -> int:
    """Poll Get-NetAdapter until the adapter is visible; return IfIndex."""
    attempts = attempts if attempts is not None else config.ADAPTER_READY_ATTEMPTS
    delay = delay if delay is not None else config.ADAPTER_READY_DELAY_SEC
    last_exc: Optional[Exception] = None

    for i in range(attempts):
        try:
            idx = get_ifindex_by_name(adapter_name)
            log.info("NetAdapter %r visible (IfIndex=%s)", adapter_name, idx)
            return idx
        except (PowerShellError, ValueError) as exc:
            last_exc = exc
            log.debug("Waiting for NetAdapter %r (%s/%s)...", adapter_name, i + 1, attempts)
            time.sleep(delay)

    raise TimeoutError(f"NetAdapter {adapter_name!r} never appeared") from last_exc


# ---------------------------------------------------------------------------
# Route manager
# ---------------------------------------------------------------------------

@dataclass
class RouteManager:
    """
    Configures IP + high-priority routes on the virtual adapter and
    remembers enough state to undo the changes.
    """

    adapter_name: str = field(default_factory=lambda: config.ADAPTER_NAME)
    ip_address: str = field(default_factory=lambda: config.ADAPTER_IP)
    prefix_length: int = field(default_factory=lambda: config.ADAPTER_PREFIX_LENGTH)
    virtual_gateway: str = field(default_factory=lambda: config.VIRTUAL_GATEWAY)
    interface_metric: int = field(default_factory=lambda: config.INTERFACE_METRIC)
    route_metric: int = field(default_factory=lambda: config.ROUTE_METRIC)
    prefixes: tuple[str, ...] = field(default_factory=lambda: config.HIGH_PRIORITY_PREFIXES)

    # Filled in during apply()
    if_index: Optional[int] = field(default=None, init=False)
    real_gateway: Optional[DefaultGatewayInfo] = field(default=None, init=False)
    _applied: bool = field(default=False, init=False)
    _routes_installed: list[str] = field(default_factory=list, init=False)
    _protected_hosts: list[str] = field(default_factory=list, init=False)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def apply(self, if_index: Optional[int] = None, protect_hosts: Optional[list[str]] = None) -> int:
        """
        Bring the virtual interface up for tunneling.

        Args:
            if_index: Optional pre-resolved IfIndex. If omitted, resolved by name.
            protect_hosts: Optional list of IPv4 hosts (e.g. your VPN server)
                that must keep using the *real* default gateway so we do not
                create a routing loop when the tunnel endpoint is remote.

        Returns:
            The virtual adapter IfIndex.
        """
        if self._applied:
            log.warning("RouteManager.apply() called but already applied — skipping.")
            return int(self.if_index)  # type: ignore[arg-type]

        self.real_gateway = get_default_gateway()

        if if_index is not None:
            self.if_index = if_index
        else:
            self.if_index = wait_for_adapter_name(self.adapter_name)

        log.info(
            "Configuring adapter %r (IfIndex=%s) ip=%s/%s gateway=%s",
            self.adapter_name,
            self.if_index,
            self.ip_address,
            self.prefix_length,
            self.virtual_gateway,
        )

        self._enable_adapter()
        self._assign_ip()
        self._set_interface_metric()

        # Host routes for tunnel endpoints MUST be installed before the
        # high-priority defaults, otherwise packets to the VPN server would
        # be sucked into the virtual adapter (routing loop).
        for host in protect_hosts or []:
            self._protect_host(host)

        self._install_high_priority_routes()
        self._applied = True
        log.info("High-priority routing active on IfIndex=%s", self.if_index)
        return self.if_index

    def revert(self) -> None:
        """Remove routes and IP configuration we installed. Safe to call twice."""
        if not self._applied and self.if_index is None:
            return

        log.info("Reverting routing configuration for %r", self.adapter_name)
        try:
            if self.if_index is None:
                try:
                    self.if_index = get_ifindex_by_name(self.adapter_name)
                except Exception:
                    log.warning("Cannot resolve adapter for cleanup — routes may linger.")
                    self._applied = False
                    return

            self._remove_high_priority_routes()
            self._remove_protected_hosts()
            self._remove_ip()
        except Exception as exc:
            log.error("Error during route revert: %s", exc)
        finally:
            self._applied = False
            log.info("Routing configuration reverted.")

    def __enter__(self) -> "RouteManager":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.revert()

    # ------------------------------------------------------------------
    # Steps
    # ------------------------------------------------------------------

    def _enable_adapter(self) -> None:
        name = _quote(self.adapter_name)
        log.info("Enabling NetAdapter %r", self.adapter_name)
        # Enable is idempotent; ignore "already up" style failures via SilentlyContinue
        # on the status check, but still ErrorAction Stop on the enable itself only
        # when the adapter is disabled.
        _ps(
            f"$a = Get-NetAdapter -Name '{name}' -ErrorAction Stop; "
            f"if ($a.Status -ne 'Up') {{ Enable-NetAdapter -Name '{name}' -Confirm:$false -ErrorAction Stop }}"
        )

    def _assign_ip(self) -> None:
        assert self.if_index is not None
        ip = _quote(self.ip_address)
        log.info("Assigning %s/%s to IfIndex=%s", self.ip_address, self.prefix_length, self.if_index)

        # Remove any existing IPv4 addresses on this interface so re-runs are clean.
        _ps(
            f"$addrs = Get-NetIPAddress -InterfaceIndex {self.if_index} "
            f"-AddressFamily IPv4 -ErrorAction SilentlyContinue; "
            f"if ($addrs) {{ $addrs | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue }}"
        )
        _ps(
            f"New-NetIPAddress -InterfaceIndex {self.if_index} "
            f"-IPAddress '{ip}' "
            f"-PrefixLength {self.prefix_length} "
            f"-AddressFamily IPv4 "
            f"-PolicyStore ActiveStore "
            f"-ErrorAction Stop | Out-Null"
        )

    def _set_interface_metric(self) -> None:
        assert self.if_index is not None
        log.info("Setting InterfaceMetric=%s on IfIndex=%s", self.interface_metric, self.if_index)
        _ps(
            f"Set-NetIPInterface -InterfaceIndex {self.if_index} "
            f"-AddressFamily IPv4 "
            f"-AutomaticMetric Disabled "
            f"-InterfaceMetric {self.interface_metric} "
            f"-ErrorAction Stop"
        )
        # Disable weak-host / promote strong routing behaviour is left at defaults.

    def _install_high_priority_routes(self) -> None:
        assert self.if_index is not None
        hop = _quote(self.virtual_gateway)

        for prefix in self.prefixes:
            pfx = _quote(prefix)
            log.info(
                "Installing route %s via %s ifIndex=%s metric=%s",
                prefix,
                self.virtual_gateway,
                self.if_index,
                self.route_metric,
            )
            # Remove any stale copy first.
            _ps(
                f"$r = Get-NetRoute -InterfaceIndex {self.if_index} "
                f"-DestinationPrefix '{pfx}' -AddressFamily IPv4 "
                f"-ErrorAction SilentlyContinue; "
                f"if ($r) {{ $r | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue }}"
            )
            _ps(
                f"New-NetRoute -DestinationPrefix '{pfx}' "
                f"-InterfaceIndex {self.if_index} "
                f"-NextHop '{hop}' "
                f"-RouteMetric {self.route_metric} "
                f"-AddressFamily IPv4 "
                f"-PolicyStore ActiveStore "
                f"-ErrorAction Stop | Out-Null"
            )
            self._routes_installed.append(prefix)

    def _protect_host(self, host: str) -> None:
        """
        Pin a /32 host route to the real physical gateway so traffic to that
        host (e.g. your VPN server) never enters the virtual adapter.
        """
        if not self.real_gateway:
            log.warning("Cannot protect host %s — no real default gateway known.", host)
            return

        host_q = _quote(host)
        hop_q = _quote(self.real_gateway.next_hop)
        idx = self.real_gateway.if_index
        prefix = f"{host}/32"
        pfx_q = _quote(prefix)

        log.info(
            "Protecting host %s via real gateway %s (ifIndex=%s)",
            host,
            self.real_gateway.next_hop,
            idx,
        )
        _ps(
            f"$r = Get-NetRoute -DestinationPrefix '{pfx_q}' -AddressFamily IPv4 "
            f"-ErrorAction SilentlyContinue; "
            f"if ($r) {{ $r | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue }}"
        )
        _ps(
            f"New-NetRoute -DestinationPrefix '{pfx_q}' "
            f"-InterfaceIndex {idx} "
            f"-NextHop '{hop_q}' "
            f"-RouteMetric 1 "
            f"-AddressFamily IPv4 "
            f"-PolicyStore ActiveStore "
            f"-ErrorAction Stop | Out-Null"
        )
        self._protected_hosts.append(host)

    def _remove_high_priority_routes(self) -> None:
        if self.if_index is None:
            return
        for prefix in list(self._routes_installed) or list(self.prefixes):
            pfx = _quote(prefix)
            log.info("Removing route %s from IfIndex=%s", prefix, self.if_index)
            try:
                _ps(
                    f"$r = Get-NetRoute -InterfaceIndex {self.if_index} "
                    f"-DestinationPrefix '{pfx}' -AddressFamily IPv4 "
                    f"-ErrorAction SilentlyContinue; "
                    f"if ($r) {{ $r | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue }}",
                    check=False,
                )
            except Exception as exc:
                log.warning("Failed to remove route %s: %s", prefix, exc)
        self._routes_installed.clear()

    def _remove_protected_hosts(self) -> None:
        for host in list(self._protected_hosts):
            pfx = _quote(f"{host}/32")
            log.info("Removing protected host route %s/32", host)
            try:
                _ps(
                    f"$r = Get-NetRoute -DestinationPrefix '{pfx}' -AddressFamily IPv4 "
                    f"-ErrorAction SilentlyContinue; "
                    f"if ($r) {{ $r | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue }}",
                    check=False,
                )
            except Exception as exc:
                log.warning("Failed to remove protected host %s: %s", host, exc)
        self._protected_hosts.clear()

    def _remove_ip(self) -> None:
        if self.if_index is None:
            return
        ip = _quote(self.ip_address)
        log.info("Removing IP %s from IfIndex=%s", self.ip_address, self.if_index)
        try:
            _ps(
                f"$a = Get-NetIPAddress -InterfaceIndex {self.if_index} "
                f"-IPAddress '{ip}' -AddressFamily IPv4 -ErrorAction SilentlyContinue; "
                f"if ($a) {{ $a | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue }}",
                check=False,
            )
        except Exception as exc:
            log.warning("Failed to remove IP: %s", exc)
