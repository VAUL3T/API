<div align="center">
    <img src="image/IMG_2811.jpeg" width="32%">
    <h1>UserInfo (VAUL3T)</h1>
    <a href="https://www.gnu.org/licenses/gpl-3.0.html">
  <img src="https://img.shields.io/badge/license-GPLv3-blue.svg" alt="License: GPL v3">
</a>
</div>
<br>

UserInfo is a free open-source scraper with easy interface and no confusing bullshit 

Copyright (C) 2025 VAUL3T
VAUL3T@proton.me

VAUL3T is an open source project dedicated to developing OSINT tools. We provide full access to the source code to support bug hunting and to demonstrate our strict zero
knowledge policy.

We guarantee that we do not collect any data that can be linked back to you.

Only in rare cases such as when enabling anti–rate limiting features we may require your Telegram username.

Please note: All our projects are licensed under (GPLv3) 

> [!NOTE]
> We are not responsible for any damange done by this programm or modified versions, 
> We only offer support and guarantee for our ORIGINAL service.

Table of Contents
------------------

1. [Further Documentation](#further-documentation)
2. [How To Use](#how-to-use)
3. [Rate Limit](#rate-limit)
4. [API](#API)
5. [Token](#Token)


Further documentation
----------------------
- Website: - 
- Telegram: https://t.me/vaul3t
- GitHub: https://github.com/VAUL3T/TiktokUserInfoBot

How to use
----------------------

* `GET /api/v0/@user/<username>` - Search for a user by username . E.g. `tiktok`.

* `GET /api/v0/@user/validate/<username>` - Validate a username. E.g. `tiktok`.

> [!NOTE]
> Make Sure to send the requests without using the (@)
>  `GET /api/v0/@user/tiktok`

## How is your informaion managed 

As we said we do not collect any data , but if you are being rate limited or request an anti rate limit you are still ram-saved 

| Saved | Time  |
|----------|------|
| rate limit  | `until rate limit is over` |
| TOKEN bind | `user saved until you request an removal` |

Token bind = Your user ID is connected to the TOKEN avoiding mass token creation

#### Logs

we have a small debug system that logs things like "/api executed" but not who executed it

in these logs no data is displayed 
But our provider has its own log system

|                               | Displayed ? | Stored ? | How long ? |
|-------------------------------|:-------:|:-----:|:-----:|
| Who you searched              |   🔴    |   🔴   |   -   |  
| When you searched             |   🔴    |   🔴   |   -   | 
| User-Agent                    |   🟢    |   🟢   |   Unkown   | 
| Who you are                   |   🔴    |   🔴   |   -   |    
| Username                      |   🔴    |   🔴   |   -   |     
| User ID                       |   🔴    |   🔴   |   -   |     
| How many searches             |   🔴    |   🔴   |   -   |  
| TimeStamp                     |   🔴    |   🔴   |   -   | 
| Errors                        |   🟢    |   🔴   |   Server Shutdown   |    
| What API called               |   🟢    |   🔴   |   Server Shutdown   |   

unlike other services we dont log any user data at all 

we dont know who you are searching , who you are and when you searched 

> [!NOTE]
> Logs are only visible until server shutdown , no logfile is created everything is only printed into the console , for provider logs we advice to use a User-Agent spoofer and a VPN , if you host this on a server like google cloud/VPS it does not matter and you can search without these

## Rate Limit

Users that are rate-limited are saved until its over (using FLASK)
7 requests per 3m

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["7 per minute"]
)
```
```python
@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        "error": f"Rate limit exceeded: {e.description}"
    }), 429
```

## API
The API is kept very simple
```python
@app.route('/api/v0/@user/<username>', methods=['GET'])
@require_token 
@limiter.limit("10 per 3 minutes")
def get_user(username):
    auth_header = request.headers.get("Authorization", "")
    
    if not auth_header.startswith("Token "):
        return jsonify({"error": "Missing or invalid Authorization header"}), 401

    scraper = TiktokUserInfo()
    return jsonify(scraper.search(username))
```
```python
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
```
```python
@app.route('/api/v0/@server/validate/<token>', methods=['GET'])
def validate_token(token):
    if token in VALID_TOKENS:
        return jsonify({"OK": "Valid Token"}), 200
    else:
        return jsonify({"error": "Invalid Token"}), 200
```

#Token
Tokens are loaded and managed simple and easy
```python
def load_tokens(filename="TOKEN.json"):
    try:
        with open(filename, "r") as f:
            data = json.load(f)
            return {entry["token"] for entry in data if "token" in entry}
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print(f"Error loading token file: {e}")
        return set()
```
```python
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
```

