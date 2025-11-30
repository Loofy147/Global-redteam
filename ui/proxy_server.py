from flask import Flask, request, jsonify
import requests
import os

app = Flask(__name__)

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")
PROXY_AUTH_TOKEN = os.environ.get("PROXY_AUTH_TOKEN")
ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"

@app.route("/api/proxy", methods=["POST"])
def proxy():
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Authorization header missing or invalid"}), 401

    token = auth_header.split(" ")[1]
    if not PROXY_AUTH_TOKEN or token != PROXY_AUTH_TOKEN:
        return jsonify({"error": "Invalid authorization token"}), 401

    if not ANTHROPIC_API_KEY:
        return jsonify({"error": "Anthropic API key not configured"}), 500

    headers = {
        "x-api-key": ANTHROPIC_API_KEY,
        "content-type": "application/json",
        "anthropic-version": "2023-06-01"
    }

    data = request.json

    try:
        response = requests.post(ANTHROPIC_API_URL, headers=headers, json=data)
        response.raise_for_status()
        return jsonify(response.json())
    except requests.exceptions.RequestException as e:
        return jsonify({"error": str(e)}), 502

if __name__ == "__main__":
    app.run(port=5001)
