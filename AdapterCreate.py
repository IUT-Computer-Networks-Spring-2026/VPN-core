import ctypes
import os



wintun = ctypes.CDLL(os.path.join(os.getcwd(), "wintun.dll"))


WINTUN_ADAPTER_TYPE_NAME = "Wintun"

def create_adapter(name : str = "vpncore"):
    
    guid = None
    adapter = wintun.WintunCreateAdapter(name, WINTUN_ADAPTER_TYPE_NAME, guid)
    
    if not adapter:
        raise Exception("Can't create Adapter")
    
    print(f"Adapter Created : {name}")
    return adapter


if __name__ == "__main__":
    try:
        adapter = create_adapter()
        
        input("Enter to delete Adapter")
        
        
        wintun.WintunDeleteAdapter(adapter)
        print("End")
        
    except Exception as e:
        print(e)




# netsh interface ip set address "vpncore" static 10.0.0.1 255.255.255.0
# route add 0.0.0.0 mask 0.0.0.0 10.0.0.1 metric 5

