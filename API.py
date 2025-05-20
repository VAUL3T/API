import json
import re
import traceback
import flask_cors
from datetime import datetime, timezone
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


def load_tokens(filename="TOKEN.json"):
    try:
        with open(filename, "r") as f:
            data = json.load(f)
            return {entry["token"] for entry in data if "token" in entry}
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error loading token file: {e}")
        return set()
        
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
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["7 per minute"]
)

class TiktokUserInfo:
    URI_BASE = 'https://www.tiktok.com/'

    
    def _error_response(self):
        return {"error": "Account not found or unable to fetch data"}

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
@limiter.limit("10 per 3 minutes")
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
