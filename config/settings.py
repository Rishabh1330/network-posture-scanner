"""Application configuration loaded from the local .env file."""

import os
from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

FIREWALL_CONFIG = os.getenv(
    "FIREWALL_CONFIG",
    str(PROJECT_ROOT / "config" / "sample_firewall.conf"),
)

REPORT_DIRECTORY = str(PROJECT_ROOT / "reports")
SCAN_RESULTS = str(Path(REPORT_DIRECTORY) / "scan_results.json")
CIS_RESULTS = str(Path(REPORT_DIRECTORY) / "cis_results.json")
FIREWALL_RESULTS = str(Path(REPORT_DIRECTORY) / "firewall_rules.json")

# Scanner upload configuration.
# NPS_* values take priority; API_* aliases keep scanner/dashboard configuration compatible.
API_BASE_URL = os.getenv("API_BASE_URL", "").strip().rstrip("/")
API_URL = os.getenv("NPS_API_URL", "").strip() or (
    f"{API_BASE_URL}/scan" if API_BASE_URL else ""
)
API_KEY = os.getenv("NPS_API_KEY", "").strip() or os.getenv("API_KEY", "").strip()