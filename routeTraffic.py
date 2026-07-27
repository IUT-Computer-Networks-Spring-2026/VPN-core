import subprocess
from typing import Optional

def _ps(command: str) -> str:
    print("=" * 80)
    print(command)
    print("=" * 80)

    result = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command
        ],
        capture_output=True,
        text=True
    )

    print("STDOUT:")
    print(result.stdout)

    print("STDERR:")
    print(result.stderr)

    if result.returncode != 0:
        raise RuntimeError(result.stderr)

    return result.stdout

def _quote(value: str) -> str:
    return value.replace("'", "''")

def _get_ifindex(adapter_name: str) -> int:
    name = _quote(adapter_name)
    out = _ps(
        f"(Get-NetAdapter -Name '{name}' -ErrorAction Stop | Select-Object -ExpandProperty ifIndex)"
    )
    return int(out)

def route(
    adapter_name: str,
    next_hop: str = "10.0.0.1",
    *,
    ip_address: str = "10.0.0.2",
    prefix_length: int = 24,
    destination_prefix: str = "0.0.0.0/0",
    interface_metric: int = 1,
    route_metric: int = 1,
) -> int:
    ifindex = _get_ifindex(adapter_name)

    ip = _quote(ip_address)
    hop = _quote(next_hop)
    prefix = _quote(destination_prefix)

    _ps(
        f"New-NetIPAddress -InterfaceIndex {ifindex} "
        f"-IPAddress '{ip}' "
        f"-PrefixLength {prefix_length} "
        f"-AddressFamily IPv4 "
        f"-ErrorAction Stop"
    )

    _ps(
        f"Set-NetIPInterface -InterfaceIndex {ifindex} "
        f"-AddressFamily IPv4 "
        f"-AutomaticMetric Disabled "
        f"-InterfaceMetric {interface_metric} "
        f"-ErrorAction Stop"
    )

    # Remove only matching tunnel routes, if any exist
    _ps(
        f"$routes = Get-NetRoute -InterfaceIndex {ifindex} "
        f"-DestinationPrefix '{prefix}' -AddressFamily IPv4 "
        f"-ErrorAction SilentlyContinue; "
        f"if ($routes) {{ $routes | Remove-NetRoute -Confirm:$false -ErrorAction Stop }}"
    )

    _ps(
        f"New-NetRoute -DestinationPrefix '{prefix}' "
        f"-InterfaceIndex {ifindex} "
        f"-NextHop '{hop}' "
        f"-RouteMetric {route_metric} "
        f"-AddressFamily IPv4 "
        f"-ErrorAction Stop"
    )

    return ifindex

def delete_route(
    adapter_name: str,
    *,
    destination_prefix: str = "0.0.0.0/0",
) -> None:
    ifindex = _get_ifindex(adapter_name)
    prefix = _quote(destination_prefix)

    _ps(
        f"$routes = Get-NetRoute -InterfaceIndex {ifindex} "
        f"-DestinationPrefix '{prefix}' -AddressFamily IPv4 "
        f"-ErrorAction SilentlyContinue; "
        f"if ($routes) {{ $routes | Remove-NetRoute -Confirm:$false -ErrorAction Stop }}"
    )