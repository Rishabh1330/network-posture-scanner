"""API Gateway ingestion Lambda for network posture reports."""
import json
import os
import uuid
from datetime import datetime, timezone
from decimal import Decimal

import boto3

table = boto3.resource("dynamodb").Table(os.environ.get("TABLE_NAME", "NetworkPostureScanner"))


def convert_numbers(value):
    if isinstance(value, list): return [convert_numbers(item) for item in value]
    if isinstance(value, dict): return {key: convert_numbers(item) for key, item in value.items()}
    return Decimal(str(value)) if isinstance(value, float) else value


def response(status_code, payload):
    return {"statusCode": status_code, "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": os.environ.get("CORS_ORIGIN", "*")}, "body": json.dumps(payload)}


def lambda_handler(event, context):
    try:
        body = json.loads(event.get("body") or "{}")
        if not isinstance(body, dict) or not isinstance(body.get("devices"), list) or not isinstance(body.get("firewall"), dict):
            return response(400, {"success": False, "message": "Expected devices (list) and firewall (object)."})
        scan_id = str(uuid.uuid4())
        received_at = datetime.now(timezone.utc).isoformat()
        # Retain the legacy scan_time shape used by the three read Lambdas.
        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        body["scan_id"] = scan_id
        body["scan_info"] = {**body.get("scan_info", {}), "scan_id": scan_id,
                             "scan_time": scan_time, "received_at": received_at}
        table.put_item(Item=convert_numbers(body))
        return response(201, {"success": True, "scan_id": scan_id, "received_at": received_at})
    except json.JSONDecodeError:
        return response(400, {"success": False, "message": "Request body must be valid JSON."})
    except Exception:
        return response(500, {"success": False, "message": "Unable to store scan."})
