from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import boto3
from boto3.dynamodb.conditions import Key, Attr
from decimal import Decimal
import os
import datetime
import io
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import re
import csv


application = Flask(__name__)
CORS(application)
bcrypt = Bcrypt(application)

SECRET_KEY = "your_secret_key"
AWS_REGION = "us-east-1"
DATA_TABLE = "Data"
USERS_TABLE = "Users"
AWS_ACCESS_KEY="AKIAY7MGW5IH3OK3PDVL"
AWS_SECRET_ACCESS_KEY="LuDel0m+pr2eM7x5E2AYN7YatcDVe7wFX5bwM6tm"
# Secret key for JWT
application.config["JWT_SECRET_KEY"] = SECRET_KEY
jwt = JWTManager(application)

# Connect to DynamoDB
dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION, aws_access_key_id=AWS_ACCESS_KEY, aws_secret_access_key=AWS_SECRET_ACCESS_KEY)
plc_data_table = dynamodb.Table(DATA_TABLE)
users_table = dynamodb.Table(USERS_TABLE)

# Helper functions for DynamoDB Decimal conversion
def convert_to_decimal(obj):
    """Convert float values to Decimal for DynamoDB"""
    if isinstance(obj, float):
        return Decimal(str(obj))
    elif isinstance(obj, dict):
        return {k: convert_to_decimal(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_to_decimal(i) for i in obj]
    return obj


def convert_from_decimal(obj):
    """Convert Decimal values back to float for JSON serialization"""
    if isinstance(obj, Decimal):
        return float(obj)
    elif isinstance(obj, dict):
        return {k: convert_from_decimal(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_from_decimal(i) for i in obj]
    return obj


def clean_value(value):
    """Remove units and convert to float"""
    if isinstance(value, (int, float)):
        return float(value)
    # Remove non-numeric characters except decimal point and minus sign
    cleaned = re.sub(r'[^\d.-]', '', str(value))
    try:
        return float(cleaned) if cleaned else 0.0
    except:
        return 0.0


@application.route("/api/latest", methods=["GET"])
def get_latest_data():
    response = plc_data_table.scan()
    items = response.get("Items", [])

    if not items:
        return jsonify({"message": "No data found"}), 404

    # Keep only records with a timestamp
    items = [i for i in items if "time" in i]

    # Convert to int and sort
    items.sort(key=lambda x: int(x["time"]), reverse=True)

    # Return the latest
    latest_item = items[0]
    return jsonify(convert_from_decimal(latest_item))


@application.route("/api/all", methods=["GET"])
def get_all_data():
    response = plc_data_table.scan()
    items = response.get('Items', [])
    
    # Handle pagination if needed
    while 'LastEvaluatedKey' in response:
        response = plc_data_table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
        items.extend(response.get('Items', []))
    
    if items:
        return jsonify(convert_from_decimal(items))
    return jsonify({"message": "No data found"}), 404


DEVICE_FREQUENCY = 5   # seconds


@application.route("/runtime-report", methods=["POST"])
def runtime_report():
    data = request.get_json()

    start = data["startTime"]
    end = data["endTime"]

    # Convert to UNIX timestamp (integer)
    start_ts = int(datetime.datetime.fromisoformat(start).timestamp())
    end_ts = int(datetime.datetime.fromisoformat(end).timestamp())

    # Query DynamoDB with filter
    response = plc_data_table.scan(
        FilterExpression=Attr('time').between(str(start_ts), str(end_ts)) & Attr('spd').ne('0')
    )
    
    rows = response.get('Items', [])
    
    # Handle pagination
    while 'LastEvaluatedKey' in response:
        response = plc_data_table.scan(
            FilterExpression=Attr('time').between(str(start_ts), str(end_ts)) & Attr('spd').ne('0'),
            ExclusiveStartKey=response['LastEvaluatedKey']
        )
        rows.extend(response.get('Items', []))

    run_count = len(rows)

    # Calculate runtime
    running_seconds = run_count * DEVICE_FREQUENCY
    running_minutes = running_seconds / 60

    return jsonify({
        "data_points": run_count,
        "running_seconds": running_seconds,
        "running_minutes": round(running_minutes, 2)
    })


@application.route("/api/debug", methods=["GET"])
def debug_data():
    """Debug endpoint to check data structure"""
    try:
        # Get item count
        response = plc_data_table.scan(Select='COUNT')
        total = response.get('Count', 0)
        
        # Get first document
        first_response = plc_data_table.scan(Limit=1)
        first = convert_from_decimal(first_response.get('Items', [{}])[0]) if first_response.get('Items') else None
        
        # Get last document (sort by timestamp)
        last_response = plc_data_table.scan(Limit=100)
        items = last_response.get('Items', [])
        if items:
            items.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            last = convert_from_decimal(items[0])
        else:
            last = None
        
        timestamp_type = type(first.get('timestamp')).__name__ if first and 'timestamp' in first else 'No timestamp field'
        
        return jsonify({
            "total_documents": total,
            "first_document": first,
            "last_document": last,
            "timestamp_field_type": timestamp_type,
            "sample_timestamp": str(first.get('timestamp')) if first and 'timestamp' in first else None
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@application.route("/api/history", methods=["GET"])
def get_history():
    try:
        start_str = request.args.get("start")
        end_str = request.args.get("end")
        tags = request.args.get("tags", "").split(",")

        # Parse start/end datetimes
        start_dt = datetime.datetime.fromisoformat(start_str)
        end_dt = datetime.datetime.fromisoformat(end_str)

        # Convert to UNIX timestamps (integer seconds)
        start_ts = int(start_dt.timestamp())
        end_ts = int(end_dt.timestamp())

        print(f"Received params - start: {start_str}, end: {end_str}, tags: {tags}")
        print(f"Parsed dates - start: {start_dt}, end: {end_dt}")
        print(f"Converted timestamps - start: {start_ts}, end: {end_ts}")

        # DynamoDB scan with filter
        response = plc_data_table.scan(
            FilterExpression=Attr('time').between(str(start_ts), str(end_ts)),
            ProjectionExpression='#t, spd, volt',
            ExpressionAttributeNames={'#t': 'time'}
        )
        
        docs = response.get('Items', [])
        
        # Handle pagination
        while 'LastEvaluatedKey' in response:
            response = plc_data_table.scan(
                FilterExpression=Attr('time').between(str(start_ts), str(end_ts)),
                ProjectionExpression='#t, spd, volt',
                ExpressionAttributeNames={'#t': 'time'},
                ExclusiveStartKey=response['LastEvaluatedKey']
            )
            docs.extend(response.get('Items', []))

        # Sort by time
        docs.sort(key=lambda x: int(x.get('time', 0)))

        print(f"Found {len(docs)} documents matching query")

        # Convert numeric timestamp string to readable format
        for d in docs:
            try:
                d["time"] = datetime.datetime.fromtimestamp(int(d["time"])).strftime("%d-%b-%Y %H:%M:%S")
                d["spd"] = float(d.get("spd", 0))
                d["volt"] = float(d.get("volt", 0))
            except Exception as e:
                print(f"Skipping invalid record: {e}")

        return jsonify(convert_from_decimal(docs))

    except Exception as e:
        print(f"❌ Error: {e}")
        return jsonify({"error": str(e)}), 500


@application.route("/api/store", methods=["POST"])
def store_reading():
    """
    Store a new sensor reading
    Body: {
        "Tank A": 84,
        "Tank B": 75,
        "Tank C": 54,
        "Pressure": "78.3 psi",
        "Temperature": "36.5 °C",
        "Flow": "8.05 L/s",
        "TT1": "57.4 °C",
        "TT2": "34.0 °C",
        "TT3": "55.8 °C",
        "TT4": "64.3 °C",
        "LT1": "4.5 L/s",
        "LT2": "4.46 L/s",
        "LT3": "7.02 L/s",
        "A": "120 psi",
        "B": "95 psi",
        "timestamp": "2024-01-01T12:00:00" (optional)
    }
    """
    try:
        data = request.json
        timestamp_str = data.get('timestamp')
        
        # Use provided timestamp or current time as string (matching your format)
        if timestamp_str:
            timestamp = timestamp_str
        else:
            timestamp = datetime.datetime.now().isoformat()
        
        # Build document with all sensor values
        document = {
            "timestamp": timestamp
        }
        
        # Add all sensor readings - keep them in original format (with units)
        sensor_fields = ['Tank A', 'Tank B', 'Tank C', 'Pressure', 'Temperature', 
                        'Flow', 'TT1', 'TT2', 'TT3', 'TT4', 'LT1', 'LT2', 'LT3', 'A', 'B']
        
        for field in sensor_fields:
            if field in data:
                document[field] = data[field]
        
        # Convert floats to Decimal for DynamoDB
        document = convert_to_decimal(document)
        
        # Put item in DynamoDB
        plc_data_table.put_item(Item=document)
        
        return jsonify({
            "success": True,
            "timestamp": timestamp
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@application.route("/api/tags", methods=["GET"])
def get_tags():
    """Get list of all available tags from the database"""
    try:
        # Get a sample document to determine available fields
        response = plc_data_table.scan(Limit=1)
        items = response.get('Items', [])
        
        if not items:
            return jsonify({"tags": []})
        
        sample = items[0]
        # Get all fields except timestamp
        tags = [key for key in sample.keys() if key not in ['timestamp']]
        return jsonify({"tags": tags})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@application.route("/api/stats", methods=["GET"])
def get_stats():
    """Get database statistics"""
    try:
        # Get count
        response = plc_data_table.scan(Select='COUNT')
        total_documents = response.get('Count', 0)
        
        # Get sample for tags
        sample_response = plc_data_table.scan(Limit=1)
        sample = sample_response.get('Items', [{}])[0] if sample_response.get('Items') else None
        tags = [key for key in sample.keys() if key not in ['timestamp']] if sample else []
        
        # Get all items to find oldest and newest
        all_response = plc_data_table.scan(Limit=100)
        all_items = all_response.get('Items', [])
        
        if all_items:
            all_items.sort(key=lambda x: x.get('timestamp', ''))
            oldest = all_items[0]
            newest = all_items[-1]
        else:
            oldest = None
            newest = None
        
        return jsonify({
            "total_documents": total_documents,
            "total_tags": len(tags),
            "tags": tags,
            "oldest_record": oldest['timestamp'] if oldest else None,
            "newest_record": newest['timestamp'] if newest else None
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@application.route("/api/export_csv", methods=["POST"])
def export_csv():
    """
    Export historical data as a CSV file.
    Expects JSON body with a 'rows' array (list of dicts).
    """
    try:
        data = request.get_json()
        rows = data.get("rows", [])

        if not rows:
            return jsonify({"error": "No data to export"}), 400

        # Create in-memory CSV
        output = io.StringIO()
        fieldnames = list(rows[0].keys())
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

        # Go back to the beginning
        output.seek(0)

        # Encode to UTF-8 for Excel readability
        return send_file(
            io.BytesIO(output.getvalue().encode("utf-8-sig")),  # 'utf-8-sig' adds BOM for Excel
            mimetype="text/csv; charset=utf-8",
            as_attachment=True,
            download_name="historical_data.csv"
        )

    except Exception as e:
        print(f"Error exporting CSV: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@application.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"message": "Username and password required"}), 400

    # Check if user exists
    response = users_table.get_item(Key={'username': username})
    if 'Item' in response:
        return jsonify({"message": "User already exists"}), 400

    hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")
    users_table.put_item(Item={
        'username': username,
        'password': hashed_pw
    })

    return jsonify({"message": "User registered successfully"}), 201


@application.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")
    print(username, password)
    
    response = users_table.get_item(Key={'username': username})
    
    if 'Item' not in response:
        return jsonify({"message": "Invalid username or password"}), 401
    
    user = response['Item']
    
    if not bcrypt.check_password_hash(user["password"], password):
        return jsonify({"message": "Invalid username or password"}), 401

    token = create_access_token(identity=username)
    return jsonify({"access_token": token, "username": username}), 200

    
@application.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    current_user_id = get_jwt_identity()
    return jsonify({"message": f"Hello user {current_user_id}, welcome to protected route!"})


if __name__ == "__main__":
    application.run(debug=True)

    