"""Dashboard configuration and local report locations."""
import os
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(PROJECT_ROOT / ".env")

API_BASE_URL = os.getenv("API_BASE_URL", "").strip().rstrip("/")
API_KEY = os.getenv("API_KEY", "").strip()
# auto = prefer AWS but transparently show the just-created local report if unavailable.
DATA_SOURCE = os.getenv("NPS_DASHBOARD_SOURCE", "auto").lower()
REPORT_DIRECTORY = PROJECT_ROOT / "reports"
