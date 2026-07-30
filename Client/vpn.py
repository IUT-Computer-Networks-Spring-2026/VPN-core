from logger import logging
from adapter import Adapter
from routing import RouteManager
import validator
import elevation



class vpn () :
    __tunnel_mode : bool 
    __proxy_mode : bool 
    log : logging
    adapter : Adapter
    rout : RouteManager
    lb_port : int

    def __init__(self):
        validator.check_os()
        self.__proxy_mode = False
        self.__tunnel_mode = False
        self.log = logging("VPNCore")
        self.adapter = None
        self.rout = None
        self.lb_port = None



    def enable_tunnel (self):
        if (self.__tunnel_mode):
            self.log.error("Tunnel mode is already enable")
            return
        if elevation.is_admin() :
                    elevation.ensure_admin()
        if not elevation.is_admin():
            self.log.error("User most be admin")
            return

        self.adapter.create()
        self.adapter.enable_adapter()
        if_index = self.adapter.wait_until_ready()
        self.adapter.start_session()
        self.rout.assign_ip(if_index=if_index)
        if self.rout.has_ip(if_index=if_index):
            self.log.info(
            "Verified: %s is assigned to %r. "
            "Check externally with: Get-NetIPAddress -InterfaceIndex %s",
            self.rout.ip_address,
            self.adapter.name,
            if_index,
            )
        else:
            self.log.error("has_ip() reports no IP on the adapter — assignment failed.")
        self.rout.create_tunnel(if_index=if_index)
        



    def disable_tunnel (self):
        if (self.__tunnel_mode):
            self.log.error("Tunnel mode is already disable")
            return
        
        try:
            self.rout.revert()
        except Exception as exc:
            self.log.error("Error while reverting routes: %s", exc)
            self.adapter.close()
            self.log.info("Cleanup complete — adapter removed.")






    def enable_proxy (self, port : int = 2018):
        if port > 65534 or port < 0 :
            self.log.error(f"invalid port : {port}")
        if (self.__proxy_mode):
            self.log.error("Proxy mode is already enable")
            return




    def disable_proxy (self):
        if (not self.__proxy_mode):
            self.log.error("Proxy mode is already disable")
            return
        