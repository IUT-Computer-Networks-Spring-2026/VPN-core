import ctypes
import json
import os
import subprocess
import sys
import time
from ctypes import wintypes
from typing import Optional



_ERROR_NO_MORE_ITEMS = 259       # receive ring is empty right now
_ERROR_HANDLE_EOF = 38           # adapter/session is shutting down
_ERROR_BUFFER_OVERFLOW = 111     # send ring is full
_WAIT_OBJECT_0 = 0               # WaitForSingleObject: event signalled
_WAIT_TIMEOUT = 0x00000102       # WaitForSingleObject: timed out

_WINTUN_MIN_RING_CAPACITY = 0x20000     # 128 KiB
_WINTUN_MAX_RING_CAPACITY = 0x4000000   # 64 MiB
_WINTUN_MAX_IP_PACKET_SIZE = 0xFFFF     # 65535 bytes


_ADAPTER_HANDLE = ctypes.c_void_p
_SESSION_HANDLE = ctypes.c_void_p
_PBYTE = ctypes.POINTER(ctypes.c_ubyte)


# handling C structure in python
class _NET_LUID(ctypes.Structure):
    _fields_ = [("Value", ctypes.c_uint64)] # 64 bit number


# error handling
class TunnelError(RuntimeError):
    pass



class Tunnel:
    
    BUFFER_SIZE: int = 65535

    DEFAULT_ADAPTER_NAME: str = "WinTun"
    
    DEFAULT_ADAPTER_ADDRESS: str = "10.8.0.2"
    DEFAULT_PREFIX_LENGTH: int = 24
    DEFAULT_GATEWAY: str = "10.8.0.1"

    DEFAULT_TUNNEL_TYPE: str = "Tunnel"
    DEFAULT_SESSION_CAPACITY: int = 0x400000  # 4 MiB
    
    DEFAULT_INTERFACE_METRIC: int = 1
    DEFAULT_ROUTE_METRIC: int = 1


    HIGH_PRIORITY_PREFIXES: tuple[str, str] = ("0.0.0.0/1", "128.0.0.0/1") # whole ipv4 address
    LOOPBACK_PREFIX: str = "127.0.0.0/8"   # never tunnelled lb

    RECEIVE_WAIT_MS: int = 500
    
    READY_ATTEMPTS: int = 40
    READY_DELAY_SEC: float = 0.25

    
    _wintun: Optional[ctypes.WinDLL] = None   # wintun
    _kernel32: Optional[ctypes.WinDLL] = None # windows
    _iphlpapi: Optional[ctypes.WinDLL] = None # network

    def __init__(self):

    
        self.is_tunnel_active: bool = False

        self.adapter_name: str = self.DEFAULT_ADAPTER_NAME
        self.adapter_address: str = self.DEFAULT_ADAPTER_ADDRESS
        self.prefix_length: int = self.DEFAULT_PREFIX_LENGTH


        self._handle: Optional[ctypes.c_void_p] = None
        self._session: Optional[ctypes.c_void_p] = None
        self._read_event: Optional[int] = None           # wait for read
        self._if_index: Optional[int] = None             # if index for power shell

        # for restoring settings
        self._routes_installed: list[str] = []           # orutes
        self._original_gateway: Optional[dict] = None    # default route
        self._server_bypass: Optional[str] = None        # server bypass (exception for routing)
        self._loopback_excluded: bool = False            # explicit 127.0.0.0/8 exclusion route

    # load .dll s files
    @classmethod
    def _load_dlls(cls): # returns ctypes.WinDLL

        # check if loaded
        if cls._wintun is not None:
            return cls._wintun


        # get the .py address
        here = os.path.dirname(os.path.abspath(__file__))

        dll_path = os.path.join(here, "wintun.dll")
        if not os.path.isfile(dll_path):
            raise FileNotFoundError(f"wintun.dll not found next to {__file__!r}")

        # load wintun.dll
        w = ctypes.WinDLL(dll_path, use_last_error=True)


        # create adapter and set variables situation
        w.WintunCreateAdapter.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.c_void_p]
        w.WintunCreateAdapter.restype = _ADAPTER_HANDLE
        w.WintunCloseAdapter.argtypes = [_ADAPTER_HANDLE]
        w.WintunCloseAdapter.restype = None
        w.WintunGetAdapterLUID.argtypes = [_ADAPTER_HANDLE, ctypes.POINTER(_NET_LUID)]
        w.WintunGetAdapterLUID.restype = None
        w.WintunGetRunningDriverVersion.argtypes = []
        w.WintunGetRunningDriverVersion.restype = wintypes.DWORD
        w.WintunStartSession.argtypes = [_ADAPTER_HANDLE, wintypes.DWORD]
        w.WintunStartSession.restype = _SESSION_HANDLE
        w.WintunEndSession.argtypes = [_SESSION_HANDLE]
        w.WintunEndSession.restype = None
        w.WintunGetReadWaitEvent.argtypes = [_SESSION_HANDLE]
        w.WintunGetReadWaitEvent.restype = wintypes.HANDLE
        w.WintunReceivePacket.argtypes = [_SESSION_HANDLE, ctypes.POINTER(wintypes.DWORD)]
        w.WintunReceivePacket.restype = _PBYTE
        w.WintunReleaseReceivePacket.argtypes = [_SESSION_HANDLE, _PBYTE]
        w.WintunReleaseReceivePacket.restype = None
        w.WintunAllocateSendPacket.argtypes = [_SESSION_HANDLE, wintypes.DWORD]
        w.WintunAllocateSendPacket.restype = _PBYTE
        w.WintunSendPacket.argtypes = [_SESSION_HANDLE, _PBYTE]
        w.WintunSendPacket.restype = None

        # loading another 2 .dll files
        k = ctypes.WinDLL("kernel32", use_last_error=True)
        k.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        k.WaitForSingleObject.restype = wintypes.DWORD

        ip = ctypes.WinDLL("iphlpapi", use_last_error=True)
        ip.ConvertInterfaceLuidToIndex.argtypes = [
            ctypes.POINTER(_NET_LUID), ctypes.POINTER(wintypes.DWORD)
        ]
        ip.ConvertInterfaceLuidToIndex.restype = wintypes.DWORD

        cls._wintun, cls._kernel32, cls._iphlpapi = w, k, ip

        w.WintunGetRunningDriverVersion()
        return w

    
    @staticmethod
    def _win_error(prefix: str):
        err = ctypes.get_last_error()
        return OSError(err, f"{prefix} (Win32 error {err}: {ctypes.FormatError(err)})")

    # run command in powershell
    @staticmethod
    def _ps(command: str, check: bool = True) : # check flag for error checking
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-Command", command],
            capture_output=True, text=True, timeout=60,
            encoding="utf-8", errors="replace",
        )
        if check and result.returncode != 0:
            raise TunnelError(
                f"PowerShell failed (exit {result.returncode}): "
                f"{(result.stderr or result.stdout).strip() or 'unknown error'}"
            )
        return (result.stdout or "").strip()

    @staticmethod
    def _q(value: str): # prevent injection
        return value.replace("'", "''")

    # validator
    @staticmethod
    def _validate_ip(ip: str):
        import ipaddress
        try:
            ipaddress.ip_address(ip)
        except ValueError as exc:
            raise ValueError(f"Invalid IP address: {ip!r}") from exc


    @staticmethod
    def _is_ipv6(packet: bytes) -> bool:
        return len(packet) >= 1 and (packet[0] >> 4) == 6

    @staticmethod
    def _validate_capacity(capacity: int):
        if capacity < _WINTUN_MIN_RING_CAPACITY or capacity > _WINTUN_MAX_RING_CAPACITY:
            raise TunnelError(
                f"Ring capacity {capacity:#x} out of range "
                f"[{_WINTUN_MIN_RING_CAPACITY:#x}, {_WINTUN_MAX_RING_CAPACITY:#x}]"
            )
        if capacity & (capacity - 1) != 0:   # power-of-two check
            raise TunnelError(f"Ring capacity {capacity:#x} must be a power of two")

    def _get_if_index(self):
        w = self._load_dlls()
        luid = _NET_LUID()
        w.WintunGetAdapterLUID(self._handle, ctypes.byref(luid))
        index = wintypes.DWORD(0) # unsigned int 4 bit : C
        status = self._iphlpapi.ConvertInterfaceLuidToIndex(
            ctypes.byref(luid), ctypes.byref(index)
        )
        # if it was OK returns zero
        if status != 0:
            raise self._win_error("ConvertInterfaceLuidToIndex failed")
        return int(index.value)

    def _wait_until_ready(self):
        last: Optional[Exception] = None
        for attempt in range(self.READY_ATTEMPTS):
            try:
                idx = self._get_if_index()
                if idx > 0:
                    return idx
            except OSError as exc:
                last = exc
            time.sleep(self.READY_DELAY_SEC)
        raise TunnelError(
            f"Adapter {self.adapter_name!r} not ready within "
            f"{self.READY_ATTEMPTS * self.READY_DELAY_SEC:.1f}s"
        ) from last

    
    def _read_default_gateway(self):
        script = r"""
        $r = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
             Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1
        if (-not $r) { return }
        [pscustomobject]@{ if_index = $r.InterfaceIndex; next_hop = $r.NextHop } |
            ConvertTo-Json -Compress
        """
        raw = self._ps(script,False)
        if not raw:
            return None
        try:
            data = json.loads(raw)
        except (ValueError, TypeError):
            return None
        return {"if_index": int(data["if_index"]), "next_hop": str(data["next_hop"])}

    def _enable_adapter(self):
        name = self._q(self.adapter_name)
        self._ps(
            f"$a = Get-NetAdapter -Name '{name}' -ErrorAction Stop; "
            f"if ($a.Status -ne 'Up') {{ Enable-NetAdapter -Name '{name}' "
            f"-Confirm:$false -ErrorAction Stop }}"
        )

    def _assign_ip(self):
        idx = self._if_index
        ip = self._q(self.adapter_address)
        
        self._ps(
            f"$a = Get-NetIPAddress -InterfaceIndex {idx} -AddressFamily IPv4 "
            f"-ErrorAction SilentlyContinue; if ($a) {{ $a | Remove-NetIPAddress "
            f"-Confirm:$false -ErrorAction SilentlyContinue }}",
            False,
        )
        self._ps(
            f"New-NetIPAddress -InterfaceIndex {idx} -IPAddress '{ip}' "
            f"-PrefixLength {self.prefix_length} -AddressFamily IPv4 "
            f"-PolicyStore ActiveStore -ErrorAction Stop | Out-Null"
        )

    def _set_interface_metric(self):
        self._ps(
            f"Set-NetIPInterface -InterfaceIndex {self._if_index} -AddressFamily IPv4 "
            f"-AutomaticMetric Disabled -InterfaceMetric {self.DEFAULT_INTERFACE_METRIC} "
            f"-ErrorAction Stop"
        )

    def _install_redirect_routes(self):
        hop = self._q(self.DEFAULT_GATEWAY)
        for prefix in self.HIGH_PRIORITY_PREFIXES:
            pfx = self._q(prefix)
            self._ps(
                f"$r = Get-NetRoute -InterfaceIndex {self._if_index} "
                f"-DestinationPrefix '{pfx}' -AddressFamily IPv4 -ErrorAction SilentlyContinue; "
                f"if ($r) {{ $r | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue }}",
                False,
            )
            self._ps(
                f"New-NetRoute -DestinationPrefix '{pfx}' -InterfaceIndex {self._if_index} "
                f"-NextHop '{hop}' -RouteMetric {self.DEFAULT_ROUTE_METRIC} -AddressFamily IPv4 "
                f"-PolicyStore ActiveStore -ErrorAction Stop | Out-Null"
            )
            self._routes_installed.append(prefix)

    def _remove_redirect_routes(self):
        for prefix in list(self._routes_installed) or list(self.HIGH_PRIORITY_PREFIXES):
            pfx = self._q(prefix)
            self._ps(
                f"$r = Get-NetRoute -InterfaceIndex {self._if_index} "
                f"-DestinationPrefix '{pfx}' -AddressFamily IPv4 -ErrorAction SilentlyContinue; "
                f"if ($r) {{ $r | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue }}",
                False,
            )
        self._routes_installed.clear()

    def _remove_ip(self) :
        if self._if_index is None:
            return
        ip = self._q(self.adapter_address)
        self._ps(
            f"$a = Get-NetIPAddress -InterfaceIndex {self._if_index} -IPAddress '{ip}' "
            f"-AddressFamily IPv4 -ErrorAction SilentlyContinue; "
            f"if ($a) {{ $a | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue }}",
            False,
        )

    def _add_server_bypass(self, dest_ip: str): # exception for routing
        if not self._original_gateway:
            return
        self._validate_ip(dest_ip)
        pfx = self._q(f"{dest_ip}/32")
        hop = self._q(self._original_gateway["next_hop"])
        idx = self._original_gateway["if_index"]
        self._ps(
            f"$r = Get-NetRoute -DestinationPrefix '{pfx}' -AddressFamily IPv4 "
            f"-ErrorAction SilentlyContinue; if ($r) {{ $r | Remove-NetRoute "
            f"-Confirm:$false -ErrorAction SilentlyContinue }}",
            False,
        )
        self._ps(
            f"New-NetRoute -DestinationPrefix '{pfx}' -InterfaceIndex {idx} "
            f"-NextHop '{hop}' -RouteMetric 1 -AddressFamily IPv4 "
            f"-PolicyStore ActiveStore -ErrorAction Stop | Out-Null"
        )
        self._server_bypass = dest_ip

    def _remove_server_bypass(self):
        if not self._server_bypass:
            return
        pfx = self._q(f"{self._server_bypass}/32")
        self._ps(
            f"$r = Get-NetRoute -DestinationPrefix '{pfx}' -AddressFamily IPv4 "
            f"-ErrorAction SilentlyContinue; if ($r) {{ $r | Remove-NetRoute "
            f"-Confirm:$false -ErrorAction SilentlyContinue }}",

            False,
        )
        self._server_bypass = None

    # keep loopback (127.0.0.0/8)
    def _exclude_loopback(self):
        pfx = self._q(self.LOOPBACK_PREFIX)
        existing = self._ps(
            f"Get-NetRoute -DestinationPrefix '{pfx}' -AddressFamily IPv4 "
            f"-ErrorAction SilentlyContinue | Select-Object -First 1",
            False,
        )
        if existing:
            return
        self._ps(
            f"New-NetRoute -DestinationPrefix '{pfx}' -InterfaceIndex 1 "
            f"-NextHop '0.0.0.0' -RouteMetric 1 -AddressFamily IPv4 "
            f"-PolicyStore ActiveStore -ErrorAction Stop | Out-Null"
        )
        self._loopback_excluded = True

    def _restore_loopback(self):
        if not self._loopback_excluded:
            return
        pfx = self._q(self.LOOPBACK_PREFIX)
        self._ps(
            f"$r = Get-NetRoute -DestinationPrefix '{pfx}' -InterfaceIndex 1 "
            f"-AddressFamily IPv4 -ErrorAction SilentlyContinue; if ($r) {{ $r | "
            f"Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue }}",
            False,
        )
        self._loopback_excluded = False

    
    def _is_admin(self):
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False  # if the check fails, assume we are not elevated

    # request and handle administrator privileges (elevate PowerShell via UAC)
    def _ensure_admin(self):
        if self._is_admin():
            return True

        # not elevated
        params = " ".join(f'"{arg}"' for arg in sys.argv)
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command",
             f"Start-Process -FilePath '{sys.executable}' "
             f"-ArgumentList '{params}' -Verb RunAs"],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            raise TunnelError(
                f"Administrator elevation failed: "
                f"{result.stderr.strip() or 'user declined the UAC prompt'}"
            )

        # stop this non-elevated one
        sys.exit(0)

   # public APIs
    def create(self, adapter_name: Optional[str] = None, adapter_address: Optional[str] = None):
        if self.is_tunnel_active:
            raise TunnelError("Tunnel is already active")

        # creating an adapter and editing routes needs administrator rights
        self._ensure_admin()

        self.adapter_name = adapter_name or self.DEFAULT_ADAPTER_NAME
        self.adapter_address = adapter_address or self.DEFAULT_ADAPTER_ADDRESS
        self._validate_ip(self.adapter_address)

        w = self._load_dlls()
        try:
            self._handle = w.WintunCreateAdapter(
                self.adapter_name, self.DEFAULT_TUNNEL_TYPE, None
            )
            if not self._handle:
                raise self._win_error("WintunCreateAdapter failed")

            self._enable_adapter()
            self._if_index = self._wait_until_ready()

            
            self._validate_capacity(self.DEFAULT_SESSION_CAPACITY)
            self._session = w.WintunStartSession(self._handle, self.DEFAULT_SESSION_CAPACITY)
            if not self._session:
                raise self._win_error("WintunStartSession failed")
            self._read_event = w.WintunGetReadWaitEvent(self._session)

            self._assign_ip()

            self._original_gateway = self._read_default_gateway()

            self._set_interface_metric()
            self._install_redirect_routes()
            self._exclude_loopback()

            self.is_tunnel_active = True
        except Exception:
            self._teardown()
            raise

    def add_bypass(self, dest_ip: str):
        if not self.is_tunnel_active:
            raise TunnelError("Tunnel is not active")
        self._add_server_bypass(dest_ip)

    def send(self, packet: bytes):
    
        if not self.is_tunnel_active:
            raise TunnelError("Cannot send: tunnel is not active")
        if not packet:
            return False
        if self._is_ipv6(packet):
            return False
        if len(packet) > _WINTUN_MAX_IP_PACKET_SIZE:
            raise TunnelError(
                f"Packet too large ({len(packet)} bytes > "
                f"max IP packet size {_WINTUN_MAX_IP_PACKET_SIZE})"
            )

        w = self._load_dlls()
        buf = w.WintunAllocateSendPacket(self._session, len(packet))
        if not buf:
            err = ctypes.get_last_error()
            if err == _ERROR_BUFFER_OVERFLOW:
                return False
            if err == _ERROR_HANDLE_EOF:
                raise TunnelError("Wintun session is terminating (send)")
            raise self._win_error("WintunAllocateSendPacket failed")
        ctypes.memmove(buf, packet, len(packet))
        w.WintunSendPacket(self._session, buf)
        return True

    def receive(self):
        if not self.is_tunnel_active:
            raise TunnelError("Cannot receive: tunnel is not active")

        w = self._load_dlls()
        size = wintypes.DWORD(0)
        ptr = w.WintunReceivePacket(self._session, ctypes.byref(size))
        if ptr:
            try:
                # size.value is always <= BUFFER_SIZE for Wintun packets.
                data = ctypes.string_at(ptr, min(size.value, self.BUFFER_SIZE))
            finally:
                w.WintunReleaseReceivePacket(self._session, ptr)
            
            if self._is_ipv6(data):
                return None
            return data

        err = ctypes.get_last_error()
        if err == _ERROR_NO_MORE_ITEMS:
            self._wait_for_read(self.RECEIVE_WAIT_MS)
            return None
        if err == _ERROR_HANDLE_EOF:
            raise TunnelError("Wintun session is terminating (receive)")
        raise self._win_error("WintunReceivePacket failed")

    def _wait_for_read(self, timeout_ms: int):
        if not self._read_event:
            return False
        self._load_dlls()
        result = self._kernel32.WaitForSingleObject(self._read_event, timeout_ms)
        if result == _WAIT_OBJECT_0:
            return True
        if result == _WAIT_TIMEOUT:
            return False
        return False

    def close(self) :
        self._teardown()

    def _teardown(self) -> None:
        self.is_tunnel_active = False

        #.
        if self._if_index is not None:
            for step in (self._remove_server_bypass,
                         self._restore_loopback,
                         self._remove_redirect_routes,
                         self._remove_ip):
                try:
                    step()
                except Exception as exc:  # keep tearing down
                    pass

        
        if self._session is not None:
            try:
                self._load_dlls().WintunEndSession(self._session)
            except Exception as exc:
                pass
            self._session = None
            self._read_event = None

       
        if self._handle is not None:
            try:
                self._load_dlls().WintunCloseAdapter(self._handle)
            except Exception as exc:
                pass
            self._handle = None

        self._if_index = None
        self._original_gateway = None
        self._routes_installed.clear()

    # with block
    def __enter__(self):
        return self
    def __exit__(self, exc_type, exc, tb):
        self.close()
