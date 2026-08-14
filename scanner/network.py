"""Local Wi-Fi/LAN discovery with ARP enrichment and lightweight TCP enumeration."""
import ipaddress
import json
import platform
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

from .utils import get_hostname

COMMON_PORTS = {21: "ftp", 22: "ssh", 23: "telnet", 53: "dns", 80: "http", 443: "https", 445: "microsoft-ds", 161: "snmp", 3389: "rdp", 3306: "mysql", 5432: "postgresql"}


def local_wifi_network():
    """Return active Wi-Fi subnet, then another active LAN adapter if Wi-Fi is unavailable."""
    if platform.system() != "Windows":
        raise RuntimeError("Automatic Wi-Fi detection is currently Windows-only. Use --targets CIDR.")
    command = ("Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*'} | "
               "Select-Object InterfaceAlias,IPAddress,PrefixLength | Sort-Object @{Expression={if($_.InterfaceAlias -match 'Wi-Fi|Wireless|WLAN'){0}else{1}}} | ConvertTo-Json -Compress")
    try:
        output = subprocess.run(["powershell", "-NoProfile", "-Command", command], capture_output=True, text=True, timeout=20, check=True).stdout
        interfaces = json.loads(output or "[]")
        if isinstance(interfaces, dict):
            interfaces = [interfaces]
        chosen = interfaces[0]
        return ipaddress.ip_network(f"{chosen['IPAddress']}/{chosen['PrefixLength']}", strict=False), chosen.get("InterfaceAlias", "local adapter")
    except (subprocess.SubprocessError, json.JSONDecodeError, KeyError, IndexError, ValueError):
        # Get-NetIPAddress may be unavailable in constrained PowerShell sessions. ipconfig
        # is available on standard Windows installations and provides the same IPv4/mask data.
        try:
            output = subprocess.run(["ipconfig"], capture_output=True, text=True, timeout=8, check=True).stdout
            blocks = re.split(r"\r?\n\s*\r?\n", output)
            candidates = []
            for block in blocks:
                ip = re.search(r"IPv4 Address[^:]*:\s*(\d+\.\d+\.\d+\.\d+)", block)
                mask = re.search(r"Subnet Mask[^:]*:\s*(\d+\.\d+\.\d+\.\d+)", block)
                header_match = re.search(r"^\s*((?:Wireless LAN|Ethernet) adapter .+?):\s*$", block, re.MULTILINE | re.IGNORECASE)
                header = header_match.group(1) if header_match else "local adapter"
                if ip and mask:
                    candidates.append((0 if re.search(r"Wireless|Wi-Fi|WLAN", header, re.I) else 1, header, ip.group(1), mask.group(1)))
            _, adapter, ip_address, subnet_mask = sorted(candidates)[0]
            try:
                wlan_output = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True, timeout=5).stdout
                wlan_name = re.search(r"^\s*Name\s*:\s*(.+)$", wlan_output, re.MULTILINE)
                if wlan_name:
                    adapter = f"Wi-Fi: {wlan_name.group(1).strip()}"
            except (OSError, subprocess.SubprocessError):
                pass
            return ipaddress.ip_network((ip_address, subnet_mask), strict=False), adapter.rstrip(":")
        except (subprocess.SubprocessError, IndexError, ValueError):
            raise RuntimeError("Could not identify an active Wi-Fi/LAN IPv4 subnet. Use --targets <authorized CIDR>.") from None


def _ping(ip, timeout):
    command = ["ping", "-n", "1", "-w", str(max(100, int(timeout * 1000))), ip] if platform.system() == "Windows" else ["ping", "-c", "1", "-W", "1", ip]
    try:
        return subprocess.run(command, capture_output=True, timeout=timeout + 1).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _arp_entries(network):
    """Read local ARP cache after discovery to get MAC addresses for local devices."""
    try:
        output = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    entries = {}
    for ip, mac in re.findall(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:-]{17})", output):
        if ipaddress.ip_address(ip) in network and mac.lower() != "ff-ff-ff-ff-ff-ff":
            entries[ip] = mac.replace("-", ":").upper()
    return entries


def _banner(ip, port, timeout):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as connection:
            connection.settimeout(timeout)
            value = connection.recv(160).decode("utf-8", errors="replace").strip()
            return value.replace("\n", " ")[:160] or "No banner returned"
    except OSError:
        return "Banner unavailable"


def _scan_host(ip, ports, timeout):
    reachable, open_ports = _ping(ip, timeout), []
    for port, service in ports.items():
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                reachable = True
                open_ports.append({"port": port, "service": service, "banner": _banner(ip, port, timeout)})
        except OSError:
            continue
    return ip, reachable, open_ports


def scan_network(targets, ports=None, timeout=0.5, workers=32, network=None):
    """Discover local hosts using ICMP/TCP and ARP; only reachable/ARP-visible hosts are returned."""
    ports, discovered = ports or COMMON_PORTS, {}
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(_scan_host, ip, ports, timeout) for ip in targets]
        for future in as_completed(futures):
            ip, reachable, open_ports = future.result()
            if reachable:
                discovered[ip] = open_ports
    arp = _arp_entries(network) if network else {}
    for ip in arp:
        discovered.setdefault(ip, [])
    devices = []
    for ip, open_ports in discovered.items():
        mac = arp.get(ip)
        devices.append({"ip": ip, "hostname": get_hostname(ip), "state": "up", "mac_address": mac,
                        "mac_vendor": "Unknown (offline OUI lookup unavailable)" if mac else None,
                        "discovery_methods": ["arp" if ip in arp else "icmp/tcp", *(["tcp"] if open_ports else [])],
                        "ports": open_ports})
    return sorted(devices, key=lambda d: tuple(int(x) for x in d["ip"].split(".")))
