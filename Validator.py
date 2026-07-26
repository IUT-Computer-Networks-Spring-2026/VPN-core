import ipaddress

def validate_host_port(ip: str, port: int):
    try:
        ipaddress.ip_address(ip)
    except ValueError as e:
        raise ValueError("Invalid IP address") from e

    if not isinstance(port, int):
        raise TypeError("Port must be an integer")

    if not (1 <= port <= 65535):
        raise ValueError("Port must be between 1 and 65535")
