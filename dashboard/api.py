"""Dashboard data source: AWS REST API when available, otherwise local scan reports."""
import json

import requests

try:  # Supports both `streamlit run dashboard/app.py` and package-based tests.
    from .config import API_BASE_URL, API_KEY, DATA_SOURCE, REPORT_DIRECTORY
except ImportError:
    from config import API_BASE_URL, API_KEY, DATA_SOURCE, REPORT_DIRECTORY


def _read_json(name):
    path = REPORT_DIRECTORY / name
    with path.open(encoding="utf-8") as report:
        return json.load(report)


def _local_data():
    scan = _read_json("scan_results.json")
    return (scan.get("devices", []), _read_json("firewall_rules.json"),
            _read_json("cis_results.json"), "Local scan reports", None)


def _aws_data():
    if not API_BASE_URL or not API_KEY:
        raise RuntimeError("API_BASE_URL or API_KEY is not configured.")
    headers = {"x-api-key": API_KEY, "Content-Type": "application/json"}
    responses = []
    for endpoint in ("devices", "firewall-rules", "cis-results"):
        response = requests.get(f"{API_BASE_URL}/{endpoint}", headers=headers, timeout=10)
        response.raise_for_status()
        responses.append(response.json().get("data"))
    return (*responses, "AWS API Gateway", None)


def get_dashboard_data():
    """Return devices, firewall, CIS results, source label, and optional AWS error."""
    if DATA_SOURCE in {"auto", "aws"}:
        try:
            return _aws_data()
        except (requests.RequestException, RuntimeError, ValueError) as error:
            if DATA_SOURCE == "aws":
                raise RuntimeError(f"AWS data source failed: {error}") from error
            try:
                devices, firewall, cis, source, _ = _local_data()
                return devices, firewall, cis, source, str(error)
            except FileNotFoundError as local_error:
                raise RuntimeError("AWS is unavailable and no local scan reports exist. Run the scanner first.") from local_error
    if DATA_SOURCE == "local":
        return _local_data()
    raise RuntimeError("NPS_DASHBOARD_SOURCE must be auto, aws, or local.")
