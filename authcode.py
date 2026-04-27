from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt
import requests
import uvicorn

app = FastAPI()
security = HTTPBearer()

# 🔹 AUTH0 CONFIG (use your values)
AUTH0_DOMAIN = "dev-0qeti821xhcmegti.us.auth0.com"
API_AUDIENCE = "https://appian-api"
ALGORITHMS = ["RS256"]


# 🔐 Verify token (FIXED: dynamic JWKS)
def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials

    try:
        unverified_header = jwt.get_unverified_header(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token header")

    # 🔥 Fetch JWKS dynamically (IMPORTANT FIX)
    jwks_url = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"
    
    jwks = requests.get(jwks_url).json()

    rsa_key = {}
    for key in jwks.get("keys", []):
        if key["kid"] == unverified_header.get("kid"):
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"],
            }

    if not rsa_key:
        raise HTTPException(status_code=401, detail="Key not found")

    try:
        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=ALGORITHMS,
            audience=API_AUDIENCE,
            issuer=f"https://{AUTH0_DOMAIN}/",
        )
        return payload

    except Exception as e:
        raise HTTPException(status_code=401, detail=str(e))


# 🧪 Health check
@app.get("/")
def home():
    return {"status": "API is running"}


# 🔍 Debug endpoint (use this to get 'sub')
@app.get("/debug")
def debug(payload=Depends(verify_token)):
    return payload


# 🔹 FAKE DATABASE (update after getting sub)
FAKE_DB = {
    "google-oauth2|104868545882126744833": {
        "balance": 7000,
        "currency": "INR",
        "transactions": [
            {"id": 1, "amount": -500, "desc": "Shopping"},
            {"id": 2, "amount": 2000, "desc": "Salary"},
        ],
    }
}


# 🔐 User-based API
@app.get("/accounts")
def get_accounts(payload=Depends(verify_token)):
    user_id = payload.get("sub")

    if not user_id:
        return {"error": "User ID not found in token"}

    data = FAKE_DB.get(user_id)

    if not data:
        return {
            "error": "No data for this user",
            "user_id": user_id
        }

    return {
        "user_id": user_id,
        "account": data
    }


# 🚀 Run locally
if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)