import json
import time
import re
import traceback
import flask_cors
from datetime import datetime, timezone, timedelta
import requests
import pycountry
from functools import wraps
from flask import Flask, render_template
from flask import abort
from flask import request
from flask import Flask, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

def load_tokens(filename="TOKEN.json"):
    try:
        with open(filename, "r") as f:
            data = json.load(f)
            return {entry["token"] for entry in data if "token" in entry}
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error loading token file: {e}")
        return set()

def reload_tokens():
    global VALID_TOKENS
    VALID_TOKENS = load_tokens()
    print(f"[Token Reload] Loaded {len(VALID_TOKENS)} tokens.")

def require_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Token "):
            return jsonify({"error": "Missing or invalid Authorization header"}), 401
        token = auth_header.replace("Token ", "").strip()
        if token not in VALID_TOKENS:
            return jsonify({"error": "Invalid Token"}), 403
        return f(*args, **kwargs)
    return decorated

VALID_TOKENS = load_tokens()
last_token_refresh_time = None

def token_and_ip_key():
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Token ", "").strip() if auth_header.startswith("Token ") else "no-token"
    ip = request.remote_addr or "unknown-ip"
    return f"{token}:{ip}"

limiter = Limiter(
    app=app,
    key_func=token_and_ip_key,
    default_limits=["30 per minute"]
)

class TiktokUserInfo:
    URI_BASE = 'https://www.tiktok.com/'

    def _error_response(self):
        return {"error": "Account not found or unable to fetch data"}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/autho')
def autho():
    return render_template('autho.html')

@app.route('/server')
def server():
    return render_template('server.html')

@app.route('/legal')
def legal():
    return render_template('legal.html')

@app.route("/api/v0/@server/@admin/token/reload_token", methods=["POST"])
def trigger_token_reload():
    global last_token_refresh_time

    if request.headers.get("X-API-Key") != "XXXXXXXXXXX":
        abort(403)

    reload_tokens()
    last_token_refresh_time = datetime.now(timezone.utc).isoformat()

    return jsonify({
        "status": "reloaded",
        "tokens": len(VALID_TOKENS),
        "refreshed_at": last_token_refresh_time
    }), 200

@app.route('/api/v0/server/token/last_token_reload', methods=["GET"])
def get_last_token_refresh_time():
    global last_token_refresh_time

    if last_token_refresh_time is None:
        return jsonify({"message": "Token refresh has not been triggered yet."}), 404

    return jsonify({"last_token_refresh": last_token_refresh_time}), 200

@app.route('/api/v0/@user/<username>', methods=['GET'])
@require_token
@limiter.limit("10 per 3 minutes")
def get_user(username):
    auth_header = request.headers.get("Authorization", "")

    if not auth_header.startswith("Token "):
        return jsonify({"error": "Missing or invalid Authorization header"}), 401

    scraper = TiktokUserInfo()
    return jsonify(scraper.search(username))

@app.route('/api/v0/@user/validate/<username>', methods=['GET'])
@require_token
def validate_tiktok_user(username):
    scraper = TiktokUserInfo()
    result = scraper.search(username)

    if "error" in result:
        return jsonify({
            "valid": False,
            "error": result["error"]
        }), 404

    return jsonify({
        "valid": True,
        "username": f"@{username}"
    })

@app.route('/api/v0/@server/validate/<token>', methods=['GET'])
def validate_token(token):
    if token in VALID_TOKENS:
        return jsonify({"OK": "Valid Token"}), 200
    else:
        return jsonify({"error": "Invalid Token"}), 200


@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        "error": f"Rate limit exceeded: {e.description}"
    }), 429

if __name__ == "__main__":
    reload_tokens()
    app.run(debug=True, use_reloader=False)
