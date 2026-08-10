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
    Returns the latest valid scan.
    Ignores old records that don't contain scan_info.
    """

    valid_items = []

    for item in items:

        scan_info = item.get("scan_info")

        if not scan_info:
            continue

        scan_time = scan_info.get("scan_time")

        if not scan_time:
            continue

        valid_items.append(item)

    if not valid_items:
        return None

    return max(
        valid_items,
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
                    "message": "No valid scan reports found."
                })
            }

        firewall = latest_scan.get("firewall", {})

        return {
            "statusCode": 200,
            "headers": {
                "Content-Type": "application/json"
            },
            "body": json.dumps({
                "success": True,
                "rule_count": len(firewall.get("rules", [])),
                "data": firewall
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