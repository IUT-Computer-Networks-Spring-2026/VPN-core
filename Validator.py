import ipaddress

def validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError as e:
        raise ValueError(f"Invalid IP address: '{ip}'") from e

def validate_port(port: int) -> bool:
    if not isinstance(port, int):
        raise TypeError(f"Port must be an integer, got {type(port).__name__}")
    
    if not (1 <= port <= 65535):
        raise ValueError(f"Port must be between 1 and 65535, got {port}")
    
    return True

def validate_host_port(ip: str, port: int) -> bool:
    validate_ip(ip)
    validate_port(port)
    return True

