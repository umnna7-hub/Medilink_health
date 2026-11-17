
from flask import Flask, jsonify, request
from collections import defaultdict, deque
import time

app = Flask(__name__)

# Store request timestamps separately for each IP address
request_history = defaultdict(deque)

# Security settings
RATE_LIMIT = 5
TIME_WINDOW = 60
ANOMALY_WINDOW = 10


@app.route("/")
def home():
    return jsonify({
        "message": "MediLink Rate Limiting Lab",
        "status": "running"
    })


@app.route("/demo")
def demo():

    client_ip = request.remote_addr
    current_time = time.time()

    timestamps = request_history[client_ip]

    # Remove requests older than 60 seconds
    while timestamps and current_time - timestamps[0] > TIME_WINDOW:
        timestamps.popleft()

    # Record this request
    timestamps.append(current_time)

    # Detect unusually rapid requests
    recent_requests = [
        timestamp for timestamp in timestamps
        if current_time - timestamp <= ANOMALY_WINDOW
    ]

    if len(recent_requests) >= RATE_LIMIT:
        print(f"ANOMALY DETECTED: Rapid requests from {client_ip}")

    # Apply rate limiting
    if len(timestamps) > RATE_LIMIT:
        print(f"RATE LIMIT EXCEEDED: {client_ip}")

        return jsonify({
            "status": "blocked",
            "message": "Too many requests. Please try again later."
        }), 429

    return jsonify({
        "status": "success",
        "message": "Request accepted",
        "requests_in_window": len(timestamps)
    })


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5003, debug=False)
