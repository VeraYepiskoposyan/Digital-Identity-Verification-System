from fastapi import FastAPI
from pydantic import BaseModel
from pyexpat.errors import messages
from fastapi import HTTPException
from sign import sign_credential
from verify import verify_credential
import base64
import uuid
from datetime import datetime
from database import conn, cursor
import json
import qrcode

app = FastAPI()

ALLOWED_TYPES = [
    "passport",
    "driver_license",
    "student_id",
    "employee_id"
]

# 📦 Define input model
class Credential(BaseModel):
    credential_type: str
    name: str
    document_id: str
    expiry: str
    id: str | None = None
    issued_at: str | None = None


def save_credential(data, signature):
    try:
        with open("credential.json", "r") as f:
            credential = json.load(f)
    except:
        credential = []

    credential.append({
        "credential": data,
        "signature": signature
    })

    with open("credential.json", "w") as f:
        json.dump(credential, f, indent=4)

def revoke_load():
    try:
        with open("revoked.json", "r") as f:
            return json.load(f)
    except:
        return []

def revoke_id(cred_id):
    revoked = revoke_load()
    revoked.append(cred_id)

    with open("revoked.json", "w") as f:
        json.dump(revoked, f, indent=4)

# 🔐 ISSUE ENDPOINT
@app.post("/issue")
def issue_credential(credential: Credential):
    data = credential.dict()
    if data["credential_type"] not in ALLOWED_TYPES:
        raise HTTPException(
            status_code=400,
            detail="Invalid credential type"
        )

    #Adding extra fields
    data["id"] = str(uuid.uuid4())
    data["issued_at"] = datetime.now().isoformat()

    signature = sign_credential(data)

    # Convert signature to string (for JSON)
    signature_b64 = base64.b64encode(signature).decode()

    save_credential(data, signature_b64)

    qr_file= generate_qr_code(data["id"])

    return {
        "credential": data,
        "signature": signature_b64,
        "qr_code": qr_file
    }

def load_credential():
    try:
        with open("credential.json", "r") as f:
            return json.load(f)
    except:
        return []

def generate_qr_code(cred_id):
    qr_data = f"http://127.0.0.1:8000/verify_id/{cred_id}"

    qr = qrcode.make(qr_data)

    filename = f"{cred_id}.png"

    qr.save(filename)

    return filename

# 🔍 VERIFY ENDPOINT
class VerifyRequest(BaseModel):
    credential: Credential
    signature: str


@app.post("/verify")
def verify(verify_request: VerifyRequest):
    data = verify_request.credential.dict()

    # Convert back from string → bytes
    signature = base64.b64decode(verify_request.signature)

    is_valid = verify_credential(data, signature)

    revoked = revoke_load()

    is_revoked = data.get("id") in revoked

    expire_date = datetime.strptime(
        data["expiry"],
        "%Y"
    )

    is_expired = datetime.now() > expire_date

    return{
        "valid": (
            is_valid
            and not is_revoked
            and not is_expired
        ),
        "revoked": is_revoked,
        "expired": is_expired
    }

@app.post("/revoke/{cred_id}")
def revoke(cred_id: str):
    revoke_id(cred_id)
    return {"message": f"Credential {cred_id} has been revoked"}

@app.get("/credential/{cred_id}")
def get_credential(cred_id: str):
    credentials = load_credential()

    for cred in credentials:
        if cred["credential"].get("id") == cred_id:
            return {"credential": cred}

    return {"error": f"Credential {cred_id} not found"}

@app.get("/verify_id/{cred_id}")
def verify_by_id(cred_id: str):

    credentials = load_credential()

    for item in credentials:

        credential = item["credential"]
        signature_b64 = item["signature"]

        if credential.get("id") == cred_id:
            signature = base64.b64decode(signature_b64)
            is_valid = verify_credential(credential, signature)

            revoked = revoke_load()

            is_revoked = cred_id in revoked

            expire_date = datetime.strptime(
                item["expiry"],
                "%Y"
            )

            is_expired = datetime.now() > expire_date

            return {
                "credential": credential,
                "valid": (
                    is_valid
                    and not is_revoked
                    and not is_expired
                ),
                "revoked": is_revoked,
                "expired": is_expired
            }

    return {"error": f"Credential {cred_id} not found"}

