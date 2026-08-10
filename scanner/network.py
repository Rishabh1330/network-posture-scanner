import nmap
from .utils import get_hostname

# Create one scanner object
scanner = nmap.PortScanner()


def scan_network(target="127.0.0.1"):
    """
    Scan a target and return a list of discovered devices.
    """

    scanner.scan(
        hosts=target,
        arguments="-sV"
    )

    devices = []

    for host in scanner.all_hosts():

        device = {
            "ip": host,
            "hostname": get_hostname(host),
            "state": scanner[host].state(),
            "ports": []
        }

        if "tcp" in scanner[host]:

            for port in scanner[host]["tcp"]:

                port_info = scanner[host]["tcp"][port]

                if port_info["state"] == "open":

                    product = port_info.get("product", "")
                    version = port_info.get("version", "")
                    banner = f"{product} {version}".strip()

                    device["ports"].append({

                        "port": port,
                        "service": port_info.get("name", "Unknown"),
                        "product": product,
                        "version": version,
                        "banner": banner if banner else "Unknown"

                    })

        devices.append(device)

    return devices