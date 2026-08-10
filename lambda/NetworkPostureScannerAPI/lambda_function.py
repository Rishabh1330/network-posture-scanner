import json
import uuid
import boto3
from decimal import Decimal
from datetime import datetime


# ============================================================
# DynamoDB
# ============================================================

dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table("NetworkPostureScanner")


# ============================================================
# Convert floats to Decimal
# ============================================================

def convert_numbers(obj):

    if isinstance(obj, list):
        return [
            convert_numbers(item)
            for item in obj
        ]

    if isinstance(obj, dict):
        return {
            key: convert_numbers(value)
            for key, value in obj.items()
        }

    if isinstance(obj, float):
        return Decimal(str(obj))

    return obj


# ============================================================
# Lambda Handler
# ============================================================

def lambda_handler(event, context):

    try:

        # ----------------------------------------------------
        # Read request body
        # ----------------------------------------------------

        body = json.loads(
            event.get("body", "{}")
        )

        # ----------------------------------------------------
        # Generate unique scan ID
        # ----------------------------------------------------

        scan_id = str(
            uuid.uuid4()
        )

        # ----------------------------------------------------
        # Generate server-side scan timestamp
        # ----------------------------------------------------

        scan_time = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        # ----------------------------------------------------
        # Create scan information
        # ----------------------------------------------------

        body["scan_id"] = scan_id

        body["scan_info"] = {
            "scan_id": scan_id,
            "scan_time": scan_time
        }

        # ----------------------------------------------------
        # Convert floats for DynamoDB
        # ----------------------------------------------------

        body = convert_numbers(body)

        # ----------------------------------------------------
        # Store scan
        # ----------------------------------------------------

        table.put_item(
            Item=body
        )

        # ----------------------------------------------------
        # Response
        # ----------------------------------------------------

        return {

            "statusCode": 200,

            "headers": {
                "Content-Type": "application/json"
            },

            "body": json.dumps({

                "success": True,

                "message":
                    "Scan stored successfully",

                "scan_id":
                    scan_id,

                "scan_time":
                    scan_time

            })

        }

    except Exception as e:

        return {

            "statusCode": 500,

            "headers": {
                "Content-Type": "application/json"
            },

            "body": json.dumps({

                "success": False,

                "message":
                    "Failed to store scan",

                "error":
                    str(e)

            })

        }