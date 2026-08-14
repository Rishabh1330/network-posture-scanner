"""HTTPS uploader for an API Gateway endpoint protected by an API key."""
import requests


def upload_report(report, api_url, api_key):
    if not api_url or not api_key:
        print("AWS upload skipped: set NPS_API_URL and NPS_API_KEY to enable it.")
        return False
    try:
        response = requests.post(api_url, json=report, headers={
            "Content-Type": "application/json", "x-api-key": api_key}, timeout=15)
        response.raise_for_status()
        print(f"AWS upload successful (HTTP {response.status_code}).")
        return True
    except requests.RequestException as error:
        print(f"AWS upload failed: {error}")
        return False
