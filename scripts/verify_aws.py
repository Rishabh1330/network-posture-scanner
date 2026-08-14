"""Safely verify Network Posture Scanner AWS read APIs without printing secrets."""
import sys
from pathlib import Path

import requests

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from config.settings import API_BASE_URL, API_KEY  # noqa: E402


def main():
    if not API_BASE_URL or not API_KEY:
        raise SystemExit("AWS configuration missing: set API_BASE_URL and API_KEY in the root .env file.")
    headers = {"x-api-key": API_KEY}
    failed = False
    for endpoint in ("devices", "firewall-rules", "cis-results"):
        try:
            response = requests.get(f"{API_BASE_URL}/{endpoint}", headers=headers, timeout=10)
            response.raise_for_status()
            payload = response.json()
            print(f"GET /{endpoint}: HTTP {response.status_code}; records: {payload.get('count', payload.get('rule_count', payload.get('check_count', '?')))}")
        except requests.RequestException as error:
            failed = True
            print(f"GET /{endpoint}: FAILED ({error})")
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
