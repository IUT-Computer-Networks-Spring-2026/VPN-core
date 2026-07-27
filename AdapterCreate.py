import ctypes
import os
import sys

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


wintun.WintunCloseAdapter.argtypes = [ctypes.c_void_p]
wintun.WintunCloseAdapter.restype = None

WINTUN_TUNNEL_TYPE = "Wintun"

def create_adapter(name: str = "vpncore"):
    adapter = wintun.WintunCreateAdapter(name, WINTUN_TUNNEL_TYPE, None)
    if not adapter:
        raise OSError("WintunCreateAdapter failed")
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