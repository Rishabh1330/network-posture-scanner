import requests
from config import API_BASE_URL, API_KEY

HEADERS = {
    "x-api-key": API_KEY,
    "Content-Type": "application/json"
}


def get_devices():

    response = requests.get(
        f"{API_BASE_URL}/devices",
        headers=HEADERS,
        timeout=10
    )

    response.raise_for_status()

    return response.json()["data"]


def get_firewall():

    response = requests.get(
        f"{API_BASE_URL}/firewall-rules",
        headers=HEADERS,
        timeout=10
    )

    response.raise_for_status()

    return response.json()["data"]


def get_cis_results():

    response = requests.get(
        f"{API_BASE_URL}/cis-results",
        headers=HEADERS,
        timeout=10
    )

    response.raise_for_status()

    return response.json()["data"]