"""Command-line entry point for authorized network posture assessments."""
import argparse
import ipaddress
from datetime import datetime, timezone

from config.settings import API_KEY, API_URL, CIS_RESULTS, FIREWALL_CONFIG, FIREWALL_RESULTS, SCAN_RESULTS
from .aws_client import upload_report
from .benchmark_checks import run_all_checks
from .config_parser import parse_firewall_config
from .network import local_wifi_network, scan_network
from .utils import count_open_ports, print_header, save_json


def targets_from_argument(value):
    """Accept one IPv4 address, CIDR (max 256 hosts), or comma-separated IP list."""
    if "," in value:
        return [str(ipaddress.ip_address(item.strip())) for item in value.split(",")]
    if "/" in value:
        network = ipaddress.ip_network(value, strict=False)
        hosts = list(network.hosts())
        if len(hosts) > 1024:
            raise argparse.ArgumentTypeError("CIDR target is limited to 1,024 hosts; supply a smaller authorized range.")
        return [str(host) for host in hosts]
    return [str(ipaddress.ip_address(value))]


def main():
    parser = argparse.ArgumentParser(description="Network Posture Scanner: use only on authorized assets.")
    parser.add_argument("--targets", type=targets_from_argument,
                        help="Override auto Wi-Fi discovery with an authorized IPv4, CIDR (up to 1,024 hosts), or IP list")
    parser.add_argument("--firewall-config", default=FIREWALL_CONFIG)
    parser.add_argument("--upload", action="store_true", help="POST JSON to NPS_API_URL using NPS_API_KEY")
    args = parser.parse_args()
    started = datetime.now(timezone.utc)
    if args.targets:
        targets, network, adapter = args.targets, None, "manual target list"
    else:
        network, adapter = local_wifi_network()
        targets = [str(host) for host in network.hosts()]
        if len(targets) > 1024:
            parser.error(f"Detected {network} ({len(targets)} hosts). Use --targets with a smaller authorized range.")
    print_header("NETWORK POSTURE SCANNER")
    print(f"Network: {network or 'manual targets'} ({adapter})")
    print(f"Scanning {len(targets)} address(es) with ICMP, TCP, and local ARP discovery...")
    devices = scan_network(targets, network=network)
    firewall = parse_firewall_config(args.firewall_config)
    results = run_all_checks(devices, firewall)
    report = {"schema_version": "1.0", "scan_info": {"target": targets, "network": str(network) if network else None,
              "adapter": adapter, "scan_time": started.isoformat(),
              "discovery_method": "ICMP + common TCP connect + local ARP cache"},
              "devices": devices, "firewall": firewall, "cis_results": results}
    save_json(report, SCAN_RESULTS)
    save_json(results, CIS_RESULTS)
    save_json(firewall, FIREWALL_RESULTS)
    passed = sum(r["status"] == "PASS" for r in results)
    print_header("SCAN SUMMARY")
    print(f"Hosts scanned: {len(devices)} | Open ports: {count_open_ports(devices)} | Checks: {passed}/{len(results)} pass")
    if args.upload:
        upload_report(report, API_URL, API_KEY)


if __name__ == "__main__":
    main()
