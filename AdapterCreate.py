import ctypes
import os



wintun = ctypes.CDLL(os.path.join(os.getcwd(), "wintun.dll"))


WINTUN_ADAPTER_TYPE_NAME = "Wintun"

def create_adapter(name : str):
    
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
