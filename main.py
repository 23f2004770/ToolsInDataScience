from fastapi import FastAPI, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import jwt
from jwt.exceptions import ExpiredSignatureError, InvalidSignatureError, InvalidTokenError

app = FastAPI()

# --- ASSIGNED CONFIGURATION ---
ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-go2q2nl6.apps.exam.local"

# Your exact assigned public key
PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""

# --- REQUEST / RESPONSE SCHEMAS ---
class TokenRequest(BaseModel):
    token: str

class ValidTokenResponse(BaseModel):
    valid: bool = True
    email: str
    sub: str
    aud: str

class InvalidTokenResponse(BaseModel):
    valid: bool = False

# --- ENDPOINT ---
@app.post(
    "/verify", 
    response_model=ValidTokenResponse,
    responses={401: {"model": InvalidTokenResponse}}
)
async def verify_token(payload: TokenRequest):
    try:
        # jwt.decode handles signature verification, expiration (exp), 
        # issuer (iss), and audience (aud) checks simultaneously.
        decoded_claims = jwt.decode(
            payload.token,
            PUBLIC_KEY,
            algorithms=["RS256"],
            audience=AUDIENCE,
            issuer=ISSUER,
            options={"require": ["exp", "iss", "aud", "sub"]} # Strict presence checks
        )

        # Ensure 'email' exists in the payload safely
        email = decoded_claims.get("email", "")

        return {
            "valid": True,
            "email": email,
            "sub": decoded_claims.get("sub"),
            "aud": decoded_claims.get("aud")
        }

    except (ExpiredSignatureError, InvalidSignatureError, InvalidTokenError) as e:
        # Catches expired, tampered signatures, wrong audience, wrong issuer, or malformed JWTs
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"valid": False}
        )
