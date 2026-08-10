import os
import json
import socket
from datetime import datetime


def get_hostname(ip):
    """
    Resolve hostname from IP address.
    Returns 'Unknown' if hostname cannot be resolved.
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Unknown"


def save_json(report, filename="reports/scan_results.json"):
    """
    Save a Python dictionary as a formatted JSON file.

    Parameters:
        report (dict): Data to save
        filename (str): Output JSON file path
    """

    # Create reports directory if it doesn't exist
    os.makedirs(os.path.dirname(filename), exist_ok=True)

    # Add scan timestamp if not already present for dict-based reports
    if isinstance(report, dict):
        report.setdefault(
            "scan_time",
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )

    with open(filename, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    print(f"\n✅ Report saved successfully: {filename}")


def count_open_ports(devices):
    """
    Count total number of open ports discovered.
    """
    total = 0

    for device in devices:
        total += len(device.get("ports", []))

    return total


def print_header(title):
    """
    Print a formatted section header.
    """
    print("\n" + "=" * 60)
    print(title.center(60))
    print("=" * 60)