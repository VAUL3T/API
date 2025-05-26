import json
import time
import re
import traceback
import flask_cors
from datetime import datetime, timezone, timedelta
import requests
import pycountry
from functools import wraps
from flask import Flask, render_template, send_from_directory, Response
from flask import abort
from flask import request
from flask import Flask, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_cors import CORS
from collections import deque
import threading

#DATA.json

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)
CORS(app, origins=["https://sqx.pythonanywhere.com"])
MAINTENANCE_MODE = True

REQUEST_LOG = deque(maxlen=1000)
UNDER_ATTACK = False
ATTACK_END_TIME = None
ATTACK_LOCK = threading.Lock()

def load_tokens(filename="TOKEN.json"):
    try:
        with open(filename, "r") as f:
            data = json.load(f)
            token_map = {}
            for entry in data:
                if "token" in entry and "expires" in entry:
                    try:
                        expires = datetime.fromisoformat(entry["expires"].replace("Z", "+00:00"))
                        token_map[entry["token"]] = {"expires": expires, "userID": entry.get("userID")}
                    except ValueError:
                        print(f"Invalid expiry format: {entry}")
            return token_map
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error loading token file: {e}")
        return {}

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

        token_data = VALID_TOKENS.get(token)
        if not token_data:
            return jsonify({"error": "Invalid Token"}), 403

        if datetime.now(timezone.utc) > token_data["expires"]:
            return jsonify({"error": "Token expired"}), 403

        return f(*args, **kwargs)
    return decorated

def block_suspicious_user_agents(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ua = request.headers.get("User-Agent", "")
        if len(ua) > 500:
            return jsonify({"error": "User-Agent too long"}),403
        suspicious_keywords = ["curl", "python", "scrapy", "libwww", "WinNT4.0", "PalmOS"]
        if any(keyword in ua.lower() for keyword in suspicious_keywords):
            return jsonify({"error": "User-Agent invalid"}), 403
        return f(*args, **kwargs)
    return decorated_function

VALID_TOKENS = load_tokens()
last_token_refresh_time = None
USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_.]{2,24}$')

def validate_username(f):
    @wraps(f)
    def wrapper(username, *args, **kwargs):
        if not USERNAME_PATTERN.match(username):
            return jsonify({"error": "Invalid username format"}), 400
        return f(username, *args, **kwargs)
    return wrapper

def global_key():
    return "global"

limiter = Limiter(
    app=app,
    key_func=token_and_ip_key,
    default_limits=["30 per minute"]
)

@app.before_request
@limiter.limit("100 per minute", key_func=global_key, override_defaults=False)
def check_global_limit():
    pass

class TiktokUserInfo:
    URI_BASE = 'https://www.tiktok.com/'



    def _error_response(self):
        return {"error": "Account not found or unable to fetch data"}

@app.before_request
def check_under_attack():
    global UNDER_ATTACK, ATTACK_END_TIME

    exempt_paths = ["/api/v0/@server/@security/under_attack/status"]

    if request.path in exempt_paths:
        return

    now = time.time()

    with ATTACK_LOCK:
        while REQUEST_LOG and REQUEST_LOG[0] < now - 60:
            REQUEST_LOG.popleft()

        REQUEST_LOG.append(now)

        if UNDER_ATTACK:
            if now > ATTACK_END_TIME:
                UNDER_ATTACK = False
                print("[Under Attack] Deaktiviert")
            else:
                return render_template("attack.html"), 503

        if len(REQUEST_LOG) >= XXX:
            UNDER_ATTACK = True
            ATTACK_END_TIME = now + XXX
            print("[Under Attack] Aktiviert")
            return render_template("attack.html"), 503


@app.before_request
def check_maintenance_mode():
    if MAINTENANCE_MODE:
        protected_paths = ["/server", "/autho"]
        if request.path in protected_paths:
            return render_template("main.html"), 503

@app.before_request
def block_large_payloads():
    if request.content_length and request.content_length > 2_000_000:
        abort(413, "Payload too large")

@app.route('/')
@block_suspicious_user_agents
def index():
    return render_template('index.html')

@app.route('/legal')
@block_suspicious_user_agents
def legal():
    return render_template('legal.html')

@app.route('/autho')
@block_suspicious_user_agents
def autho():
    return render_template('autho.html')

@app.route('/privacy')
@block_suspicious_user_agents
def privacy():
    return render_template('privacy.html')

@app.route('/api/v0/@client/loading')
def load():
    return render_template('loading.html')

@app.route("/api/v0/@server/@admin/token/reload_token", methods=["POST"])
def trigger_token_reload():
    if request.headers.get("X-API-Key") != "XXXXXXXXXXXXXXXXXXXXXXXXXXX":
        abort(403)

    reload_tokens()
    refresh_time = datetime.now(timezone.utc).isoformat()

    try:
        with open("DATA.json", "w") as f:
            json.dump({"last_token_refresh": refresh_time}, f, indent=4)
    except Exception as e:
        return jsonify({"error": f"Failed to write DATA.json: {str(e)}"}), 500

    return jsonify({
        "status": "reloaded",
        "refreshed_at": refresh_time
    }), 200


@app.route('/api/v0/server/token/last_token_reload', methods=["GET"])
def get_last_token_refresh_time():
    try:
        with open("DATA.json", "r") as f:
            data = json.load(f)
            if "last_token_refresh" in data:
                return jsonify({"last_token_refresh": data["last_token_refresh"]}), 200
            else:
                return jsonify({"message": "No refresh time found in file."}), 200
    except FileNotFoundError:
        return jsonify({"message": "DATA.json not found."}), 404
    except json.JSONDecodeError:
        return jsonify({"message": "Invalid JSON in DATA.json."}), 500


@app.route('/api/v0/@user/<username>', methods=['GET'])
@limiter.limit("20 per minute")
@require_token
@validate_username
def get_user(username):
    auth_header = request.headers.get("Authorization", "")

    if not auth_header.startswith("Token "):
        return jsonify({"error": "Missing or invalid Authorization header"}), 401

    scraper = TiktokUserInfo()
    return jsonify(scraper.search(username))

@app.route('/api/v0/@user/test/<username>', methods=['GET'])
@limiter.limit("3 per hour")
@validate_username
def get_user_test(username):
    scraper = TiktokUserInfo()
    data = scraper.search(username)

    data.pop("Profile Picture", None)

    return Response(
        json.dumps(data, indent=2),
        mimetype='application/json'
    )

@app.route('/api/v0/@user/country/<username>', methods=['GET'])
@require_token
@validate_username
def get_user_country(username):
    scraper = TiktokUserInfo()
    user_data = scraper.search(username)

    if "error" in user_data:
        return jsonify({"error": user_data["error"]}), 404

    country_with_flag = user_data.get("Country", "Unknown")

    country_name = re.sub(r'[\U0001F1E6-\U0001F1FF]{2}', '', country_with_flag).strip()

    return jsonify({
        "username": f"@{username}",
        "country": country_name
    }), 200

@app.route('/api/v0/@user/validate/<username>', methods=['GET'])
@require_token
@validate_username
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

@app.route('/api/v0/@server/rce/static/logo')
def get_logo():
    return send_from_directory('static', 'logo.png')

@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template("rate.html", error=e.description), 429

if __name__ == "__main__":
    reload_tokens()
    app.run(debug=True, use_reloader=False)
