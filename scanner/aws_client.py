import requests

API_URL = "https://04l7zkg3oi.execute-api.ap-south-1.amazonaws.com/prod/scan"


def upload_report(report):
    """
    Upload scan report to AWS API Gateway.
    """

    try:
        response = requests.post(
            API_URL,
            json=report,
            headers={
                "Content-Type": "application/json"
            },
            timeout=15
        )

        print("\nAWS Upload")
        print("-" * 40)
        print(f"URL         : {API_URL}")
        print(f"Status Code : {response.status_code}")

        try:
            print("Response:")
            print(response.json())
        except Exception:
            print(response.text)

        return response.status_code == 200

    except requests.exceptions.RequestException as e:
        print("\nAWS Upload Failed")
        print(e)
        return False