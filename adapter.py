from __future__ import annotations

import ctypes
import os
import time
from ctypes import wintypes
from typing import Optional

import config
from logging_setup import get_logger
import powershell

log = get_logger("Adapter")



_ERROR_NO_MORE_ITEMS = 259       # receive ring empty — wait on read event
_ERROR_HANDLE_EOF = 38           # session / adapter shutting down
_ERROR_BUFFER_OVERFLOW = 111     # send ring full
_WAIT_OBJECT_0 = 0
_WAIT_TIMEOUT = 0x00000102

_WINTUN_MIN_RING_CAPACITY = 0x20000      # 128 KiB
_WINTUN_MAX_RING_CAPACITY = 0x4000000    # 64 MiB
_WINTUN_MAX_IP_PACKET_SIZE = 0xFFFF

_WINTUN_ADAPTER_HANDLE = ctypes.c_void_p
_WINTUN_SESSION_HANDLE = ctypes.c_void_p
_PBYTE = ctypes.POINTER(ctypes.c_ubyte)


class _NET_LUID(ctypes.Structure):
    _fields_ = [("Value", ctypes.c_uint64)]


_wintun: Optional[ctypes.WinDLL] = None
_kernel32: Optional[ctypes.WinDLL] = None
_iphlpapi: Optional[ctypes.WinDLL] = None


def _check_capacity(capacity: int) -> None:
    if capacity < _WINTUN_MIN_RING_CAPACITY or capacity > _WINTUN_MAX_RING_CAPACITY:
        raise ValueError(
            f"SESSION_CAPACITY {capacity:#x} out of range "
            f"[{_WINTUN_MIN_RING_CAPACITY:#x}, {_WINTUN_MAX_RING_CAPACITY:#x}]"
        )
    if capacity & (capacity - 1) != 0:
        raise ValueError(f"SESSION_CAPACITY {capacity:#x} must be a power of two")


def _last_error() -> int:
    return ctypes.get_last_error()


def _win_error(prefix: str = "Wintun call failed") -> OSError:
    err = _last_error()
    return OSError(err, f"{prefix} (Win32 error {err}: {ctypes.FormatError(err)})")


def _load_dlls(dll_path: Optional[str] = None) -> ctypes.WinDLL:

    global _wintun, _kernel32, _iphlpapi

    if _wintun is not None:
        return _wintun

    path = dll_path or config.WINTUN_DLL_PATH
    if not os.path.isfile(path):
        raise FileNotFoundError(f"wintun.dll not found at '{path}'. ")

    log.info("Loading wintun.dll from %s", path)

    wintun = ctypes.WinDLL(path, use_last_error=True)


    wintun.WintunCreateAdapter.argtypes = [
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        ctypes.c_void_p,
    ]
    wintun.WintunCreateAdapter.restype = _WINTUN_ADAPTER_HANDLE

    wintun.WintunOpenAdapter.argtypes = [wintypes.LPCWSTR]
    wintun.WintunOpenAdapter.restype = _WINTUN_ADAPTER_HANDLE

    wintun.WintunCloseAdapter.argtypes = [_WINTUN_ADAPTER_HANDLE]
    wintun.WintunCloseAdapter.restype = None

    wintun.WintunGetAdapterLUID.argtypes = [
        _WINTUN_ADAPTER_HANDLE,
        ctypes.POINTER(_NET_LUID),
    ]
    wintun.WintunGetAdapterLUID.restype = None

    wintun.WintunGetRunningDriverVersion.argtypes = []
    wintun.WintunGetRunningDriverVersion.restype = wintypes.DWORD

    # --- Session -----------------------------------------------------------
    wintun.WintunStartSession.argtypes = [_WINTUN_ADAPTER_HANDLE, wintypes.DWORD]
    wintun.WintunStartSession.restype = _WINTUN_SESSION_HANDLE

    wintun.WintunEndSession.argtypes = [_WINTUN_SESSION_HANDLE]
    wintun.WintunEndSession.restype = None

    wintun.WintunGetReadWaitEvent.argtypes = [_WINTUN_SESSION_HANDLE]
    wintun.WintunGetReadWaitEvent.restype = wintypes.HANDLE

    # --- Packet I/O --------------------------------------------------------
    wintun.WintunReceivePacket.argtypes = [
        _WINTUN_SESSION_HANDLE,
        ctypes.POINTER(wintypes.DWORD),
    ]
    wintun.WintunReceivePacket.restype = _PBYTE

    wintun.WintunReleaseReceivePacket.argtypes = [_WINTUN_SESSION_HANDLE, _PBYTE]
    wintun.WintunReleaseReceivePacket.restype = None

    wintun.WintunAllocateSendPacket.argtypes = [_WINTUN_SESSION_HANDLE, wintypes.DWORD]
    wintun.WintunAllocateSendPacket.restype = _PBYTE

    wintun.WintunSendPacket.argtypes = [_WINTUN_SESSION_HANDLE, _PBYTE]
    wintun.WintunSendPacket.restype = None

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    _kernel32.WaitForSingleObject.restype = wintypes.DWORD

    _iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
    _iphlpapi.ConvertInterfaceLuidToIndex.argtypes = [
        ctypes.POINTER(_NET_LUID),
        ctypes.POINTER(wintypes.DWORD),
    ]
    _iphlpapi.ConvertInterfaceLuidToIndex.restype = wintypes.DWORD  # NETIO_STATUS

    _wintun = wintun

    version = wintun.WintunGetRunningDriverVersion()
    if version:
        log.info(
            "Wintun driver version %d.%d",
            (version >> 16) & 0xFFFF,
            version & 0xFFFF,
        )
    else:
        log.debug("Wintun driver not yet loaded (will load on first adapter create).")

    return wintun


def _dll() -> ctypes.WinDLL:
    if _wintun is None:
        return _load_dlls()
    return _wintun


def _luid_to_index(luid: _NET_LUID) -> int:

    if _iphlpapi is None:
        _load_dlls()
    assert _iphlpapi is not None

    index = wintypes.DWORD(0)
    status = _iphlpapi.ConvertInterfaceLuidToIndex(
        ctypes.byref(luid), ctypes.byref(index)
    )
    if status != 0:
        raise OSError(status, f"ConvertInterfaceLuidToIndex failed (status={status})")
    return int(index.value)



class Adapter:

    def __init__(
        self,
        handle: ctypes.c_void_p,
        name: str,
    ) -> None:
        self._handle = handle
        self.name = name
        self._owned = True
        self._session: Optional[ctypes.c_void_p] = None
        self._read_event: Optional[int] = None
        self._closed = False


    @classmethod
    def create(
        cls,
        name: Optional[str] = None,
        tunnel_type: Optional[str] = None,
        *,
        dll_path: Optional[str] = None,
    ) -> "Adapter":
        # Load (or reuse) wintun.dll and configure the function prototypes.
        wintun = _load_dlls(dll_path)

        name = name or config.ADAPTER_NAME
        tunnel_type = tunnel_type or config.TUNNEL_TYPE

        log.info("Creating Wintun adapter name=%r type=%r", name, tunnel_type)
        handle = wintun.WintunCreateAdapter(name, tunnel_type, None)

        if not handle:
            raise _win_error("WintunCreateAdapter failed")

        adapter = cls(handle, name)
        log.info("Adapter created: %s (handle=%s)", name, handle)

        return adapter

    def enable_adapter(self) -> None:
        name = powershell._quote(self.name)
        log.info("Enabling NetAdapter %r", self.name)
        powershell._ps(
            f"$a = Get-NetAdapter -Name '{name}' -ErrorAction Stop; "
            f"if ($a.Status -ne 'Up') {{ Enable-NetAdapter -Name '{name}' -Confirm:$false -ErrorAction Stop }}"
        )

    @property
    def handle(self) -> ctypes.c_void_p:
        self._ensure_open()
        return self._handle

    @property
    def session_active(self) -> bool:
        return self._session is not None

    @property
    def session(self) -> ctypes.c_void_p:
        if not self._session:
            raise RuntimeError("Session not started — call start_session() first")
        return self._session

    def get_if_index(self) -> int:
        wintun = _dll()
        luid = _NET_LUID()
        wintun.WintunGetAdapterLUID(self.handle, ctypes.byref(luid))
        idx = _luid_to_index(luid)
        log.debug("Adapter %s IfIndex=%s", self.name, idx)
        return idx

    def wait_until_ready(
        self,
        attempts: Optional[int] = None,
        delay: Optional[float] = None,
    ) -> int:

        attempts = attempts if attempts is not None else config.ADAPTER_READY_ATTEMPTS
        delay = delay if delay is not None else config.ADAPTER_READY_DELAY_SEC

        last_exc: Optional[Exception] = None
        for i in range(attempts):
            try:
                idx = self.get_if_index()
                if idx > 0:
                    log.info(
                        "Adapter %s ready (IfIndex=%s) after %s attempt(s)",
                        self.name,
                        idx,
                        i + 1,
                    )
                    return idx
            except OSError as exc:
                last_exc = exc
                log.debug(
                    "Adapter not ready yet (attempt %s/%s): %s",
                    i + 1,
                    attempts,
                    exc,
                )
            time.sleep(delay)

        raise TimeoutError(
            f"Adapter {self.name!r} did not become ready within "
            f"{attempts * delay:.1f}s"
        ) from last_exc


    def start_session(self, capacity: Optional[int] = None) -> None:
        if self._session:
            log.warning("Session already started; ignoring start_session().")
            return

        capacity = capacity if capacity is not None else config.SESSION_CAPACITY
        _check_capacity(capacity)

        wintun = _dll()
        log.info("Starting Wintun session (capacity=%#x)", capacity)
        session = wintun.WintunStartSession(self.handle, capacity)
        if not session:
            raise _win_error("WintunStartSession failed")

        self._session = session
        self._read_event = wintun.WintunGetReadWaitEvent(session)
        log.info("Session started (handle=%s)", session)

    def end_session(self) -> None:
        if not self._session:
            return
        log.info("Ending Wintun session")
        try:
            _dll().WintunEndSession(self._session)
        except Exception as exc:
            log.error("WintunEndSession raised: %s", exc)
        finally:
            self._session = None
            self._read_event = None


    def receive_packet(self, timeout_ms: Optional[int] = None) -> Optional[bytes]:
        wintun = _dll()
        session = self.session
        size = wintypes.DWORD(0)

        packet_ptr = wintun.WintunReceivePacket(session, ctypes.byref(size))
        if packet_ptr:
            try:
                data = ctypes.string_at(packet_ptr, size.value)
            finally:
                wintun.WintunReleaseReceivePacket(session, packet_ptr)
            return data

        err = _last_error()
        if err == _ERROR_NO_MORE_ITEMS:
            if timeout_ms is None:
                timeout_ms = config.RECEIVE_WAIT_MS
            self._wait_for_read(timeout_ms)
            return None
        if err == _ERROR_HANDLE_EOF:
            raise RuntimeError(
                "Wintun adapter/session is terminating (ERROR_HANDLE_EOF)"
            )
        raise _win_error("WintunReceivePacket failed")

    def send_packet(self, data: bytes) -> bool:
        if not data:
            return False
        if len(data) > _WINTUN_MAX_IP_PACKET_SIZE:
            raise ValueError(
                f"Packet too large ({len(data)} > {_WINTUN_MAX_IP_PACKET_SIZE})"
            )

        wintun = _dll()
        session = self.session
        buf = wintun.WintunAllocateSendPacket(session, len(data))
        if not buf:
            err = _last_error()
            if err == _ERROR_BUFFER_OVERFLOW:
                log.warning("Send ring full — dropping %s byte packet", len(data))
                return False
            if err == _ERROR_HANDLE_EOF:
                raise RuntimeError(
                    "Wintun adapter/session is terminating (ERROR_HANDLE_EOF)"
                )
            raise _win_error("WintunAllocateSendPacket failed")

        ctypes.memmove(buf, data, len(data))
        wintun.WintunSendPacket(session, buf)
        return True

    def _wait_for_read(self, timeout_ms: int) -> bool:
        if not self._read_event:
            return False
        if _kernel32 is None:
            _load_dlls()
        assert _kernel32 is not None

        result = _kernel32.WaitForSingleObject(self._read_event, timeout_ms)
        if result == _WAIT_OBJECT_0:
            return True
        if result == _WAIT_TIMEOUT:
            return False
        log.warning("WaitForSingleObject returned unexpected code %s", result)
        return False


    def close(self) -> None:

        if self._closed:
            return
        self._closed = True
        self.end_session()

        if self._handle:
            log.info("Closing Wintun adapter %s", self.name)
            try:
                _dll().WintunCloseAdapter(self._handle)
            except Exception as exc:
                log.error("WintunCloseAdapter raised: %s", exc)
            finally:
                self._handle = None

    def _ensure_open(self) -> None:
        if self._closed or not self._handle:
            raise RuntimeError("Adapter is closed")

    def __enter__(self) -> "Adapter":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass



WintunAdapter = Adapter
