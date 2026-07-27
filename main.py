import routeTraffic
import subprocess



subprocess.run(
    [
        "powershell",
        "-Command",
        'New-NetIPAddress -InterfaceAlias "vpncore" '
        '-IPAddress "10.10.0.2" '
        '-PrefixLength 24'
    ],
    check=True
)

routeTraffic.route("vpncore")
input("Enter to delete route...")
routeTraffic.delete_route("vpncore")