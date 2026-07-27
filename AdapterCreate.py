import ctypes
import os
import sys
import subprocess

wintun_dll_path = os.path.join(os.getcwd(), "wintun.dll")
if not os.path.exists(wintun_dll_path):
    print(f"wintun.dll not found in {wintun_dll_path}")
    sys.exit(1)

wintun = ctypes.WinDLL(wintun_dll_path)


wintun.WintunCreateAdapter.argtypes = [
    ctypes.c_wchar_p,   
    ctypes.c_wchar_p,   
    ctypes.c_void_p     
]
wintun.WintunCreateAdapter.restype = ctypes.c_void_p

wintun.WintunStartSession.argtypes = [
    ctypes.c_void_p,
    ctypes.c_uint32
]
wintun.WintunStartSession.restype = ctypes.c_void_p



wintun.WintunCloseAdapter.argtypes = [ctypes.c_void_p]
wintun.WintunCloseAdapter.restype = None

WINTUN_TUNNEL_TYPE = "Wintun"

SESSION_CAPACITY = 0x400000  # 4 MiB


def start_session(adapter):
    session = wintun.WintunStartSession(
        adapter,
        SESSION_CAPACITY
    )

    if not session:
        raise RuntimeError("Cannot start Wintun session")

    print("Session started.")

    return session

def create_adapter(name: str = "vpncore"):
    adapter = wintun.WintunCreateAdapter(name, WINTUN_TUNNEL_TYPE, None)
    if not adapter:
        raise OSError("WintunCreateAdapter failed")
    

    subprocess.run(
        [
            "powershell",
            "-Command",
            f'Enable-NetAdapter -Name "{name}" -Confirm:$false'
        ],

        check=True
    )

    start_session(adapter)

    print(f"Adapter created: {name}")
    return adapter

if __name__ == "__main__":
    adapter = None
    try:
        adapter = create_adapter()
        input("Press Enter to delete adapter...")
    finally:
        if adapter:
            wintun.WintunCloseAdapter(adapter)
            print("Adapter closed")