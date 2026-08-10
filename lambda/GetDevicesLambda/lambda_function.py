import json
import boto3
from decimal import Decimal
from datetime import datetime

# DynamoDB
dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table("NetworkPostureScanner")


class DecimalEncoder(json.JSONEncoder):
    """
    Converts DynamoDB Decimal objects into int/float.
    """
    def default(self, obj):
        if isinstance(obj, Decimal):

            if obj % 1 == 0:
                return int(obj)

            return float(obj)

        return super().default(obj)


def get_latest_scan(items):
    """
    Return the latest scan that contains scan_info.
    """

    valid_scans = []

    for item in items:

        if "scan_info" not in item:
            continue

        if "scan_time" not in item["scan_info"]:
            continue

        valid_scans.append(item)

    if not valid_scans:
        return None

    return max(
        valid_scans,
        key=lambda item: datetime.strptime(
            item["scan_info"]["scan_time"],
            "%Y-%m-%d %H:%M:%S"
        )
    )
def lambda_handler(event, context):

    try:

        response = table.scan()

        items = response.get("Items", [])

        latest_scan = get_latest_scan(items)

        if latest_scan is None:

            return {
                "statusCode": 404,
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": json.dumps({
                    "success": False,
                    "message": "No scan reports found."
                })
            }

        devices = latest_scan.get("devices", [])

        return {
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json"
            },
            "body": json.dumps({
                "success": True,
                "count": len(devices),
                "data": devices
            }, cls=DecimalEncoder)
        }

    except Exception as e:

        return {
            "statusCode": 500,
            "headers": {
                "Content-Type": "application/json"
            },
            "body": json.dumps({
                "success": False,
                "message": "Internal Server Error",
                "error": str(e)
            })
        }