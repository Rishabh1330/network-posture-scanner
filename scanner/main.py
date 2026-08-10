from datetime import datetime
from config.settings import (
    TARGET,
    FIREWALL_CONFIG,
    SCAN_RESULTS,
    CIS_RESULTS,
    FIREWALL_RESULTS
)

from .network import scan_network
from .config_parser import parse_firewall_config
from .benchmark_checks import run_all_checks
from .utils import (
    save_json,
    print_header,
    count_open_ports
)
from .aws_client import upload_report
# --------------------------------------------------
# Scan Start
# --------------------------------------------------

scan_start = datetime.now()

print_header("NETWORK POSTURE SCANNER v1.0")

print(f"Target        : {TARGET}")
print(f"Scan Started  : {scan_start.strftime('%Y-%m-%d %H:%M:%S')}")

# --------------------------------------------------
# Network Scan
# --------------------------------------------------

devices = scan_network(TARGET)

print_header("DISCOVERED DEVICES")

if not devices:
    print("No reachable devices found.\n")

for device in devices:

    print("-" * 50)

    print(f"IP Address : {device['ip']}")
    print(f"Hostname   : {device['hostname']}")
    print(f"Status     : {device['state']}")

    if device["ports"]:

        print("\nOpen Ports:")

        for port in device["ports"]:

            print(
                f"  {port['port']:<6}"
                f"{port['service']:<15}"
                f"{port['banner']}"
            )

    else:

        print("\nNo open ports found.")

# --------------------------------------------------
# Firewall Parsing
# --------------------------------------------------

firewall = parse_firewall_config(FIREWALL_CONFIG)

print_header("FIREWALL SUMMARY")

print(f"Firewall Rules   : {len(firewall['rules'])}")
print(f"Logging Enabled  : {firewall['logging']}")
print(f"Syslog Server    : {firewall['syslog']}")
print(f"Default Inbound  : {firewall['default_inbound']}")
print(f"Default Outbound : {firewall['default_outbound']}")

# --------------------------------------------------
# CIS Benchmark Checks
# --------------------------------------------------

results = run_all_checks(devices, firewall)

print_header("CIS BENCHMARK RESULTS")

for result in results:

    print("-" * 50)

    print(f"Check          : {result['check']}")
    print(f"Status         : {result['status']}")
    print(f"Severity       : {result['severity']}")
    print(f"Evidence       : {result['evidence']}")
    print(f"Recommendation : {result['recommendation']}")

# --------------------------------------------------
# Create Final Report
# --------------------------------------------------

report = {
    "scan_info": {
        "target": TARGET,
        "scan_time": scan_start.strftime("%Y-%m-%d %H:%M:%S")
    },
    "devices": devices,
    "firewall": firewall,
    "cis_results": results
}

# --------------------------------------------------
# Save Reports
# --------------------------------------------------

save_json(report, SCAN_RESULTS)

save_json(results, CIS_RESULTS)

save_json(firewall, FIREWALL_RESULTS)

# --------------------------------------------------
# Scan Summary
# --------------------------------------------------

pass_count = sum(1 for r in results if r["status"] == "PASS")
fail_count = sum(1 for r in results if r["status"] == "FAIL")

print_header("SCAN SUMMARY")

print(f"Devices Found      : {len(devices)}")
print(f"Open Ports Found   : {count_open_ports(devices)}")
print(f"Firewall Rules     : {len(firewall['rules'])}")
print(f"PASS Checks        : {pass_count}")
print(f"FAIL Checks        : {fail_count}")

scan_end = datetime.now()
duration = scan_end - scan_start

print(f"Scan Duration      : {duration}")

print("\nReports Generated:")
print(f"  • {SCAN_RESULTS}")
print(f"  • {CIS_RESULTS}")
print(f"  • {FIREWALL_RESULTS}")

print("\nReports Generated:")
print(f"  • {SCAN_RESULTS}")
print(f"  • {CIS_RESULTS}")
print(f"  • {FIREWALL_RESULTS}")

# --------------------------------------------------
# Upload Report to AWS
# --------------------------------------------------

print_header("AWS UPLOAD")

success = upload_report(report)

if success:
    print("✅ Scan uploaded successfully to AWS.")
else:
    print("❌ Failed to upload scan to AWS.")

print("\nNetwork Posture Scan Completed Successfully.")
print("=" * 60)