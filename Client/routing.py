from __future__ import annotations

import json

import powershell
from dataclasses import dataclass, field
from typing import Optional

import config
import validator
from logger import get_logger

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
    _ip_assigned: bool = field(default=False, init=False)
    _routes_installed: list[str] = field(default_factory=list, init=False)
    _protected_hosts: list[str] = field(default_factory=list, init=False)

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #
    def _resolve_if_index(self, if_index: Optional[int] = None) -> int:
        """Return a usable interface index.

        Priority: explicit argument > cached ``self.if_index`` > lookup by
        adapter name. The resolved value is cached on the instance.
        """
        if if_index is not None:
            self.if_index = if_index
        if self.if_index is None:
            log.debug("Resolving IfIndex for adapter %r by name", self.adapter_name)
            self.if_index = get_ifindex_by_name(self.adapter_name)
        return self.if_index

    # ------------------------------------------------------------------ #
    # 1) IP assignment
    # ------------------------------------------------------------------ #
    def assign_ip(
        self,
        ip: Optional[str] = None,
        prefix_length: Optional[int] = None,
        if_index: Optional[int] = None,
    ) -> None:
        """Assign an IPv4 address to the virtual adapter.

        Args:
            ip: IP to assign. If ``None`` the value from ``config`` (stored on
                ``self.ip_address``) is used.
            prefix_length: Subnet prefix length. Falls back to
                ``self.prefix_length`` (config) when omitted.
            if_index: Target interface index. Resolved automatically from the
                adapter name when not supplied.

        The interface is enabled first, any pre-existing IPv4 addresses are
        removed for a clean re-run, then the new address is applied.
        """
        # Resolve address / prefix, defaulting to config-backed values.
        if ip is not None:
            self.ip_address = ip
        if prefix_length is not None:
            self.prefix_length = prefix_length

        # Fail fast on a malformed address before touching the OS.
        validator.validate_ip(self.ip_address)

        idx = self._resolve_if_index(if_index)
        ip_q = powershell._quote(self.ip_address)

        log.info(
            "Assigning %s/%s to IfIndex=%s (adapter=%r)",
            self.ip_address,
            self.prefix_length,
            idx,
            self.adapter_name,
        )

        # Make sure the adapter is up before assigning an address.
        self._enable_adapter()

        # Remove any existing IPv4 addresses on this interface so re-runs are
        # clean. This is best-effort: a fresh adapter has none, and the query
        # cmdlet returns a non-zero exit code when nothing is found even with
        # -ErrorAction SilentlyContinue, so we must not treat that as fatal.
        powershell._ps(
            f"$addrs = Get-NetIPAddress -InterfaceIndex {idx} "
            f"-AddressFamily IPv4 -ErrorAction SilentlyContinue; "
            f"if ($addrs) {{ $addrs | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue }}",
            check=False,
        )
        powershell._ps(
            f"New-NetIPAddress -InterfaceIndex {idx} "
            f"-IPAddress '{ip_q}' "
            f"-PrefixLength {self.prefix_length} "
            f"-AddressFamily IPv4 "
            f"-PolicyStore ActiveStore "
            f"-ErrorAction Stop | Out-Null"
        )
        self._ip_assigned = True
        log.info("IP %s/%s assigned to IfIndex=%s", self.ip_address, self.prefix_length, idx)

    # ------------------------------------------------------------------ #
    # 2) IP status check
    # ------------------------------------------------------------------ #
    def get_assigned_ips(self, if_index: Optional[int] = None) -> list[str]:
        """Return the list of IPv4 addresses currently on the interface."""
        try:
            idx = self._resolve_if_index(if_index)
        except Exception as exc:
            log.warning("Cannot resolve adapter %r to list IPs: %s", self.adapter_name, exc)
            return []

        # -ErrorAction SilentlyContinue keeps the cmdlet quiet, and check=False
        # tolerates the non-zero exit code returned when the interface has no
        # IPv4 address yet. The wrapping array guarantees ConvertTo-Json emits
        # a JSON list even for a single address.
        raw = powershell._ps(
            f"@(Get-NetIPAddress -InterfaceIndex {idx} -AddressFamily IPv4 "
            f"-ErrorAction SilentlyContinue | "
            f"Select-Object -ExpandProperty IPAddress) | ConvertTo-Json -Compress",
            check=False,
        )
        if not raw:
            return []
        try:
            data = json.loads(raw)
        except (ValueError, TypeError):
            log.warning("Could not parse IP list from PowerShell: %r", raw)
            return []
        if not data:
            return []
        # ConvertTo-Json yields a scalar for a single address, a list otherwise.
        if isinstance(data, list):
            return [str(x) for x in data]
        return [str(data)]

    def has_ip(self, ip: Optional[str] = None, if_index: Optional[int] = None) -> bool:
        """Check whether the adapter currently has an IP assigned.

        Args:
            ip: Specific address to look for. Defaults to ``self.ip_address``
                (the configured/assigned IP). Pass an explicit value or set to
                a falsy value to instead check for *any* address.
            if_index: Target interface index (resolved by name when omitted).

        Returns:
            ``True`` when the target IP is present (or, when ``ip`` resolves to
            an empty value, when the interface has at least one IPv4 address);
            ``False`` otherwise.
        """
        target_ip = self.ip_address if ip is None else ip
        assigned = self.get_assigned_ips(if_index)

        if target_ip:
            present = target_ip in assigned
            log.info(
                "has_ip: %s %s on adapter %r (assigned=%s)",
                target_ip,
                "present" if present else "absent",
                self.adapter_name,
                assigned,
            )
            return present

        # No specific IP requested — report whether any address exists.
        present = len(assigned) > 0
        log.info("has_ip: adapter %r has %s IPv4 address(es): %s", self.adapter_name, len(assigned), assigned)
        return present

    # ------------------------------------------------------------------ #
    # 3) Routing / tunnel creation
    # ------------------------------------------------------------------ #
    def create_tunnel(
        self,
        if_index: Optional[int] = None,
        protect_hosts: Optional[list[str]] = None,
    ) -> int:
        """Install the high-priority tunnel routing.

        Redirects all traffic through the virtual adapter by installing
        split-default routes that are more specific than the existing default
        gateway. Assumes :meth:`assign_ip` has already run (the interface needs
        an on-link address for the next hop to be valid).

        Returns the interface index the routes were installed on.
        """
        if self._applied:
            log.warning("create_tunnel() called but tunnel already active — skipping.")
            return int(self.if_index)  # type: ignore[arg-type]

        idx = self._resolve_if_index(if_index)

        # Remember the real gateway so protected hosts can bypass the tunnel.
        self.real_gateway = get_default_gateway()

        log.info(
            "Creating tunnel on adapter %r (IfIndex=%s) gateway=%s prefixes=%s",
            self.adapter_name,
            idx,
            self.virtual_gateway,
            self.prefixes,
        )

        self._set_interface_metric()

        for host in protect_hosts or []:
            self._protect_host(host)

        self._install_high_priority_routes()
        self._applied = True
        log.info("High-priority routing active on IfIndex=%s", idx)
        return idx

    # Backwards/alternative name requested in the spec ("route / create_tunnel").
    def route(
        self,
        if_index: Optional[int] = None,
        protect_hosts: Optional[list[str]] = None,
    ) -> int:
        """Alias for :meth:`create_tunnel`."""
        return self.create_tunnel(if_index=if_index, protect_hosts=protect_hosts)

    # ------------------------------------------------------------------ #
    # Orchestration (kept for backwards compatibility)
    # ------------------------------------------------------------------ #
    def apply(self, if_index: Optional[int] = None, protect_hosts: Optional[list[str]] = None) -> int:
        """Assign the IP and create the tunnel in one call.

        Kept so existing callers keep working; internally it now delegates to
        the dedicated :meth:`assign_ip` and :meth:`create_tunnel` methods.
        """
        if self._applied:
            log.warning("RouteManager.apply() called but already applied — skipping.")
            return int(self.if_index)  # type: ignore[arg-type]

        idx = self._resolve_if_index(if_index)

        log.info(
            "Configuring adapter %r (IfIndex=%s) ip=%s/%s gateway=%s",
            self.adapter_name,
            idx,
            self.ip_address,
            self.prefix_length,
            self.virtual_gateway,
        )

        self.assign_ip(if_index=idx)
        self.create_tunnel(if_index=idx, protect_hosts=protect_hosts)
        return self.if_index  # type: ignore[return-value]

    def revert(self) -> None:
        if not self._applied and self.if_index is None and not self._ip_assigned:
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
            self._ip_assigned = False
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

    def _set_interface_metric(self) -> None:
        assert self.if_index is not None
        log.info("Setting InterfaceMetric=%s on IfIndex=%s", self.interface_metric, self.if_index)
        powershell._ps(
            f"Set-NetIPInterface -InterfaceIndex {self.if_index} "
            f"-AddressFamily IPv4 "
            f"-AutomaticMetric Disabled "
            f"-InterfaceMetric {self.interface_metric} "
            f"-ErrorAction Stop"
        )

        
    def _install_high_priority_routes(self) -> None:
        assert self.if_index is not None
        hop = powershell._quote(self.virtual_gateway)

        for prefix in self.prefixes:
            pfx = powershell._quote(prefix)
            log.info(
                "Installing route %s via %s ifIndex=%s metric=%s",
                prefix,
                self.virtual_gateway,
                self.if_index,
                self.route_metric,
            )

            powershell._ps(
                f"$r = Get-NetRoute -InterfaceIndex {self.if_index} "
                f"-DestinationPrefix '{pfx}' -AddressFamily IPv4 "
                f"-ErrorAction SilentlyContinue; "
                f"if ($r) {{ $r | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue }}",
                check=False,
            )
            powershell._ps(
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
        if not self.real_gateway:
            log.warning("Cannot protect host %s — no real default gateway known.", host)
            return

        host_q = powershell._quote(host)
        hop_q = powershell._quote(self.real_gateway.next_hop)
        idx = self.real_gateway.if_index
        prefix = f"{host}/32"
        pfx_q = powershell._quote(prefix)

        log.info(
            "Protecting host %s via real gateway %s (ifIndex=%s)",
            host,
            self.real_gateway.next_hop,
            idx,
        )
        powershell._ps(
            f"$r = Get-NetRoute -DestinationPrefix '{pfx_q}' -AddressFamily IPv4 "
            f"-ErrorAction SilentlyContinue; "
            f"if ($r) {{ $r | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue }}",
            check=False,
        )
        powershell._ps(
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
            pfx = powershell._quote(prefix)
            log.info("Removing route %s from IfIndex=%s", prefix, self.if_index)
            try:
                powershell._ps(
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
            pfx = powershell._quote(f"{host}/32")
            log.info("Removing protected host route %s/32", host)
            try:
                powershell._ps(
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
        ip = powershell._quote(self.ip_address)
        log.info("Removing IP %s from IfIndex=%s", self.ip_address, self.if_index)
        try:
            powershell._ps(
                f"$a = Get-NetIPAddress -InterfaceIndex {self.if_index} "
                f"-IPAddress '{ip}' -AddressFamily IPv4 -ErrorAction SilentlyContinue; "
                f"if ($a) {{ $a | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue }}",
                check=False,
            )
        except Exception as exc:
            log.warning("Failed to remove IP: %s", exc)
        self._ip_assigned = False
