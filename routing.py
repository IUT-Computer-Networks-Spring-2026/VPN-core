from __future__ import annotations

import powershell
from dataclasses import dataclass, field
from typing import Any, Optional

import config
from logging_setup import get_logger

log = get_logger("routing")




@dataclass
class DefaultGatewayInfo:
    if_index: int
    next_hop: str
    interface_alias: str = ""
    route_metric: int = 0
    interface_metric: int = 0


def get_default_gateway() -> Optional[DefaultGatewayInfo]:
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
    data = powershell._ps_json(script)
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
    name = powershell._quote(adapter_name)
    out = powershell._ps(
        f"(Get-NetAdapter -Name '{name}' -ErrorAction Stop | "
        f"Select-Object -ExpandProperty ifIndex)"
    )
    return int(out.strip())



@dataclass
class RouteManager:
    adapter_name: str = field(default_factory=lambda: config.ADAPTER_NAME)
    ip_address: str = field(default_factory=lambda: config.ADAPTER_IP)
    prefix_length: int = field(default_factory=lambda: config.ADAPTER_PREFIX_LENGTH)
    virtual_gateway: str = field(default_factory=lambda: config.VIRTUAL_GATEWAY)
    interface_metric: int = field(default_factory=lambda: config.INTERFACE_METRIC)
    route_metric: int = field(default_factory=lambda: config.ROUTE_METRIC)
    prefixes: tuple[str, ...] = field(default_factory=lambda: config.HIGH_PRIORITY_PREFIXES)


    if_index: Optional[int] = field(default=None, init=False)
    real_gateway: Optional[DefaultGatewayInfo] = field(default=None, init=False)
    _applied: bool = field(default=False, init=False)
    _routes_installed: list[str] = field(default_factory=list, init=False)
    _protected_hosts: list[str] = field(default_factory=list, init=False)

    def apply(self, if_index: Optional[int] = None, protect_hosts: Optional[list[str]] = None) -> int:
        if self._applied:
            log.warning("RouteManager.apply() called but already applied — skipping.")
            return int(self.if_index)  # type: ignore[arg-type]

        self.real_gateway = get_default_gateway()

        if if_index is not None:
            self.if_index = if_index
        else:
            log.error("value if_index of adapter is empty in class (can't find it)")
            return

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


        for host in protect_hosts or []:
            self._protect_host(host)

        self._install_high_priority_routes()
        self._applied = True
        log.info("High-priority routing active on IfIndex=%s", self.if_index)
        return self.if_index

    def revert(self) -> None:
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


    def _enable_adapter(self) -> None:
        name = powershell._quote(self.adapter_name)
        log.info("Enabling NetAdapter %r", self.adapter_name)
        powershell._ps(
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
