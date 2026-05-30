from fastapi import FastAPI
from pydantic import BaseModel
from pyexpat.errors import messages
from fastapi import HTTPException
from sign import sign_credential
from verify import verify_credential
import base64
import uuid
import json
from datetime import datetime
from database import conn, cursor
from fastapi.responses import HTMLResponse
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
import qrcode

app = FastAPI()
app.mount("/qr", StaticFiles(directory="qr_codes"), name="qr")

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
    surname: str
    date_of_birth: str
    document_id: str
    expiry: str
    id: str | None = None
    issued_at: str | None = None


def detect_fraud(document_id):

    cursor.execute("""
    SELECT * FROM credentials
    WHERE document_id = ?
    """, (document_id,))

    existing = cursor.fetchone()

    if existing:
        return True

    return False

def calculate_age(date_of_birth: str):
    birth_date = datetime.strptime(date_of_birth, "%Y-%m-%d")
    today = datetime.now()

    age = today.year - birth_date.year

    if (today.month, today.day) < (birth_date.month, birth_date.day):
        age -= 1

    return age
from datetime import datetime

def expiry_status(expiry_date_str):

    expiry_date = datetime.strptime(
        expiry_date_str,
        "%Y-%m-%d"
    )

    today = datetime.now()

    days_remaining = (expiry_date - today).days

    return days_remaining

def save_verification_log(credential_id, result):

    cursor.execute("""
    INSERT INTO verification_logs (
        credential_id,
        verification_time,
        result
    )
    VALUES (?, ?, ?)
    """, (
        credential_id,
        datetime.now().isoformat(),
        result
    ))

    conn.commit()

# 🔐 ISSUE ENDPOINT
@app.post("/issue")
def issue_credential(credential: Credential):
    data = credential.dict()
    data["credential_type"] = (
        data["credential_type"]
        .strip()
        .lower()
    )
    is_fraud = detect_fraud(
        data["document_id"]
    )

    if is_fraud:
        return {
            "error": "Possible fraud detected: duplicate document"
        }

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

    cursor.execute("""
    INSERT INTO credentials (
        id,
        credential_type,
        name,
        surname,
        date_of_birth,
        document_id,
        expiry,
        issued_at,
        signature
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data["id"],
        data["credential_type"],
        data["name"],
        data["surname"],
        data["date_of_birth"],
        data["document_id"],
        data["expiry"],
        data["issued_at"],
        signature_b64
    ))

    conn.commit()
    qr_file= generate_qr_code(data["id"])

    return {
        "credential": data,
        "signature": signature_b64,
        "qr_code": qr_file
    }

def generate_qr_code(cred_id):
    qr_data = f"http://127.0.0.1:8000/verify_page/{cred_id}"

    qr = qrcode.make(qr_data)

    filename = f"{cred_id}.png"
    filepath = f"qr_codes/{filename}"

    qr.save(filepath)

    return f"/qr/{filename}"

# 🔍 VERIFY ENDPOINT
class VerifyRequest(BaseModel):
    credential: Credential
    signature: str


@app.post("/verify")
def verify(verify_request: VerifyRequest):
    data = verify_request.credential.dict()

    # 1. Cryptographic Verification
    # Convert back from string → bytes
    signature = base64.b64decode(verify_request.signature)
    is_valid = verify_credential(data, signature)

    # 2. Database Revocation Check (Replacing revoke_load)
    cred_id = data.get("id")
    cursor.execute("SELECT 1 FROM revoked WHERE credential_id = ?", (cred_id,))
    is_revoked = cursor.fetchone() is not None

    # 3. Expiration Check
    # Note: Using %Y means your 'expiry' field must be just the year (e.g., "2030")
    try:
        expire_date = datetime.strptime(data["expiry"], "%Y-%m-%d")
        is_expired = datetime.now() > expire_date
    except Exception:
        # If the date format is wrong, we'll mark as expired for safety
        is_expired = True

    return {
        "valid": (
            is_valid
            and not is_revoked
            and not is_expired
        ),
        "revoked": is_revoked,
        "expired": is_expired
    }
@app.get("/logs", response_class=HTMLResponse)
def logs_page():
    cursor.execute("""
    SELECT id, credential_id, verification_time, result
    FROM verification_logs
    ORDER BY verification_time DESC
    """)

    rows = cursor.fetchall()

    table_rows = ""

    for row in rows:
        log_id = row[0]
        credential_id = row[1]
        verification_time = row[2]
        result = row[3]

        if result == "SUCCESS":
            badge_class = "success"
            result_text = "✅ SUCCESS"
        else:
            badge_class = "failed"
            result_text = "❌ FAILED"

        short_id = credential_id[:8] + "..." if credential_id else "N/A"

        table_rows += f"""
        <tr>
            <td>{log_id}</td>
            <td title="{credential_id}">{short_id}</td>
            <td>{verification_time}</td>
            <td><span class="badge {badge_class}">{result_text}</span></td>
        </tr>
        """

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Verification Audit Logs</title>
        <style>
            body {{
                margin: 0;
                font-family: Arial, sans-serif;
                background: #eef2f7;
                color: #1f2937;
            }}

            header {{
                background: linear-gradient(135deg, #1e3a8a, #2563eb);
                color: white;
                padding: 30px;
                text-align: center;
            }}

            .container {{
                max-width: 1000px;
                margin: 35px auto;
                background: white;
                padding: 25px;
                border-radius: 18px;
                box-shadow: 0 10px 25px rgba(0,0,0,0.08);
            }}

            table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 20px;
            }}

            th {{
                background: #1e3a8a;
                color: white;
                padding: 14px;
                text-align: left;
            }}

            td {{
                padding: 14px;
                border-bottom: 1px solid #e5e7eb;
            }}

            tr:hover {{
                background: #f9fafb;
            }}

            .badge {{
                padding: 6px 12px;
                border-radius: 999px;
                font-weight: bold;
                font-size: 13px;
            }}

            .success {{
                background: #dcfce7;
                color: #166534;
            }}

            .failed {{
                background: #fee2e2;
                color: #991b1b;
            }}

            .empty {{
                text-align: center;
                color: #6b7280;
                padding: 30px;
            }}
        </style>
    </head>

    <body>
        <header>
            <h1>Verification Audit Logs</h1>
            <p>History of credential verification attempts</p>
        </header>

        <div class="container">
            <table>
                <thead>
                    <tr>
                        <th>Log ID</th>
                        <th>Credential ID</th>
                        <th>Verification Time</th>
                        <th>Result</th>
                    </tr>
                </thead>
                <tbody>
                    {table_rows if table_rows else '<tr><td colspan="4" class="empty">No logs found</td></tr>'}
                </tbody>
            </table>
        </div>
    </body>
    </html>
    """

@app.post("/revoke/{cred_id}")
def revoke(cred_id: str):

    cursor.execute("""
    INSERT INTO revoked (credential_id)
    VALUES (?)
    """, (cred_id,))

    conn.commit()

    return {
        "message": f"Credential {cred_id} revoked"
    }

@app.get("/credentials")
def get_all_credentials():
    cursor.execute("""
    SELECT id, credential_type, name, surname, date_of_birth, document_id, expiry, issued_at
    FROM credentials
    """)

    rows = cursor.fetchall()

    credentials = []

    for row in rows:
        credentials.append({
            "id": row[0],
            "credential_type": row[1],
            "name": row[2],
            "surname": row[3],
            "date_of_birth": row[4],
            "document_id": row[5],
            "expiry": row[6],
            "issued_at": row[7]
        })

    return {"credentials": credentials}

@app.get("/verify_id/{cred_id}")
def verify_by_id(cred_id: str):
    # 1. Fetch the credential from the database
    cursor.execute("""
    SELECT id, credential_type, name, surname, date_of_birth, document_id, expiry, issued_at, signature 
    FROM credentials
    WHERE id = ?
    """, (cred_id,))

    row = cursor.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Credential not found")

    # 2. Format the data into the dictionary for verification
    credential = {
        "id": row[0],
        "credential_type": row[1],
        "name": row[2],
        "surname": row[3],
        "date_of_birth": row[4],
        "document_id": row[5],
        "expiry": row[6],
        "issued_at": row[7]
    }
    signature_b64 = row[8]

    age = calculate_age(credential["date_of_birth"])

    # 3. Cryptographic Verification
    # Convert back from string base64 -> bytes
    signature = base64.b64decode(signature_b64)
    is_valid = verify_credential(credential, signature)

    # 4. Check Revocation Status
    cursor.execute("""
    SELECT * FROM revoked
    WHERE credential_id = ?
    """, (cred_id,))

    revoked_row = cursor.fetchone()
    is_revoked = revoked_row is not None
    final_result = is_valid and not is_revoked

    save_verification_log(
        cred_id,
        "SUCCESS" if final_result else "FAILED"
    )
    # 5. Return the full status
    return {
        "credential": credential,
        "age": age,
        "valid": is_valid and not is_revoked,
        "revoked": is_revoked,
        "message": "Identity verified successfully" if (is_valid and not is_revoked) else "Verification failed"
    }

class PresentationRequest(BaseModel):
    credential_id: str
    fields: list[str]

@app.get("/verification_logs")
def get_verification_logs():

    cursor.execute("""
    SELECT *
    FROM verification_logs
    ORDER BY verification_time DESC
    """)

    rows = cursor.fetchall()

    logs = []

    for row in rows:
        logs.append({
            "log_id": row[0],
            "credential_id": row[1],
            "verification_time": row[2],
            "result": row[3]
        })

    return {"logs": logs}

@app.post("/presentation/create")
def create_presentation(request: PresentationRequest):
    cursor.execute("""
    SELECT * FROM credentials
    WHERE id = ?
    """, (request.credential_id,))

    row = cursor.fetchone()

    if not row:
        return {"error": "Credential not found"}

    credential = {
        "id": row[0],
        "credential_type": row[1],
        "name": row[2],
        "surname": row[3],
        "date_of_birth": row[4],
        "document_id": row[5],
        "expiry": row[6],
        "issued_at": row[7]
    }

    allowed_fields = [
        "id",
        "credential_type",
        "name",
        "surname",
        "date_of_birth",
        "age",
        "document_id",
        "expiry",
        "issued_at"
    ]

    age = calculate_age(credential["date_of_birth"])
    credential["age"] = age

    shared_claims = {}

    for field in request.fields:
        if field in allowed_fields:
            shared_claims[field] = credential[field]

    presentation = {
        "presentation_id": str(uuid.uuid4()),
        "credential_id": request.credential_id,
        "shared_claims": shared_claims,
        "created_at": datetime.now().isoformat()
    }

    signature = sign_credential(presentation)
    signature_b64 = base64.b64encode(signature).decode()

    cursor.execute("""
    INSERT INTO presentations (
        presentation_id,
        credential_id,
        shared_claims,
        created_at,
        signature
    )
    VALUES (?, ?, ?, ?, ?)
    """, (
        presentation["presentation_id"],
        presentation["credential_id"],
        json.dumps(shared_claims),
        presentation["created_at"],
        signature_b64
    ))

    conn.commit()

    return {
        "presentation": presentation,
        "signature": signature_b64
    }


class PresentationVerifyRequest(BaseModel):
    presentation: dict
    signature: str

@app.post("/presentation/verify")
def verify_presentation(request: PresentationVerifyRequest):
    signature = base64.b64decode(request.signature)

    is_valid_signature = verify_credential(
        request.presentation,
        signature
    )

    credential_id = request.presentation.get("credential_id")

    cursor.execute("""
    SELECT * FROM revoked
    WHERE credential_id = ?
    """, (credential_id,))

    revoked = cursor.fetchone()
    is_revoked = revoked is not None

    return {
        "valid": is_valid_signature and not is_revoked,
        "signature_valid": is_valid_signature,
        "revoked": is_revoked
    }

@app.delete("/credential/{cred_id}")
def delete_credential(cred_id: str):

    cursor.execute("""
    DELETE FROM credentials
    WHERE id = ?
    """, (cred_id,))

    conn.commit()

    return {
        "message": f"Credential {cred_id} deleted"
    }

@app.get("/ui", response_class=HTMLResponse)
def ui():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Digital Identity Verification System</title>
        <style>
            * {
                box-sizing: border-box;
            }

            body {
                margin: 0;
                font-family: Arial, sans-serif;
                background: #eef2f7;
                color: #1f2937;
            }

            header {
                background: linear-gradient(135deg, #1e3a8a, #2563eb);
                color: white;
                padding: 35px;
                text-align: center;
            }

            header h1 {
                margin: 0;
                font-size: 34px;
            }

            header p {
                margin-top: 10px;
                font-size: 16px;
                opacity: 0.9;
            }

            .container {
                max-width: 1200px;
                margin: 30px auto;
                padding: 0 20px;
            }

            .grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
                gap: 20px;
            }

            .card {
                background: white;
                border-radius: 16px;
                padding: 24px;
                box-shadow: 0 10px 25px rgba(0,0,0,0.08);
            }

            .card h2 {
                margin-top: 0;
                color: #1e3a8a;
                font-size: 22px;
            }

            input {
                width: 100%;
                padding: 12px;
                margin: 8px 0;
                border: 1px solid #d1d5db;
                border-radius: 10px;
                font-size: 14px;
            }

            input:focus {
                outline: none;
                border-color: #2563eb;
                box-shadow: 0 0 0 3px rgba(37,99,235,0.15);
            }

            button {
                width: 100%;
                padding: 12px;
                margin-top: 10px;
                border: none;
                border-radius: 10px;
                background: #2563eb;
                color: white;
                font-size: 15px;
                font-weight: bold;
                cursor: pointer;
            }

            button:hover {
                background: #1d4ed8;
            }

            .danger {
                background: #dc2626;
            }

            .danger:hover {
                background: #b91c1c;
            }

            .result-card {
                margin-top: 25px;
                background: white;
                border-radius: 16px;
                padding: 24px;
                box-shadow: 0 10px 25px rgba(0,0,0,0.08);
            }
            
            .result-box {
                background: #0f172a;
                color: #d1fae5;
                padding: 20px;
                border-radius: 12px;
                overflow-x: auto;
                font-size: 14px;
                min-height: 120px;
                white-space: pre-wrap;
            }

            pre {
                background: #0f172a;
                color: #d1fae5;
                padding: 20px;
                border-radius: 12px;
                overflow-x: auto;
                font-size: 14px;
                min-height: 120px;
            }

            .badge {
                display: inline-block;
                padding: 6px 12px;
                border-radius: 999px;
                font-size: 13px;
                font-weight: bold;
                margin-bottom: 10px;
            }

            .badge-valid {
                background: #dcfce7;
                color: #166534;
            }

            .badge-invalid {
                background: #fee2e2;
                color: #991b1b;
            }

            footer {
                text-align: center;
                margin: 30px;
                color: #6b7280;
                font-size: 14px;
            }
        </style>
    </head>

    <body>
        <header>
            <h1>Secure Digital Identity Verification System</h1>
            <p>Verifiable Credentials • Digital Signatures • QR Verification • Revocation • Fraud Detection</p>
        </header>

        <div class="container">
            <div class="grid">

                <div class="card">
                    <h2>Issue Credential</h2>
                    <input id="type" placeholder="Credential type: passport, driver_license, student_id">
                    <input id="name" placeholder="Name">
                    <input id="surname" placeholder="Surname">
                    <label>Date of Birth</label>
                    <input id="dob" type="date">
                    <input id="doc" placeholder="Document ID">
                    <label>Expiry Date</label>
                    <input id="expiry" type="date">
                    <button onclick="issueCredential()">Issue Credential</button>
                </div>

                <div class="card">
                    <h2>Verify by ID</h2>
                    <input id="verifyId" placeholder="Credential ID">
                    <button onclick="verifyById()">Verify Credential</button>
                </div>

                <div class="card">
                    <h2>Create Presentation</h2>
                    <input id="presentationId" placeholder="Credential ID">
                    <input id="fields" placeholder="Fields to reveal: name,expiry">
                    <button onclick="createPresentation()">Create Presentation</button>
                </div>

                <div class="card">
                    <h2>Revoke Credential</h2>
                    <input id="revokeId" placeholder="Credential ID">
                    <button class="danger" onclick="revokeCredential()">Revoke</button>
                </div>
                
                <div class="card">
                    <h2>Download Credential</h2>
                    <input id="downloadId" placeholder="Credential ID">
                    <button onclick="downloadCredential()">Download JSON</button>
                </div>

            </div>

            <div class="result-card">
                <h2>Result</h2>
                <div id="statusBadge"></div>
                <div id="result" class="result-box">Results will appear here...</div>
            </div>
        </div>

        <footer>
            Diploma Project Demo — Digital Identity Infrastructure Based on Verifiable Credentials
        </footer>

        <script>
            function showResult(data) {
                const result = document.getElementById("result");
                const badge = document.getElementById("statusBadge");
                
                result.innerHTML = "";
                badge.innerHTML = "";
                
                const jsonBlock = document.createElement("pre");
                jsonBlock.textContent = JSON.stringify(data, null, 2);
                jsonBlock.style.background = "transparent";
                jsonBlock.style.padding = "0";
                jsonBlock.style.margin = "0";
                jsonBlock.style.color = "#d1fae5";
                
                result.appendChild(jsonBlock);
                
                if (data.qr_code) {
                    const qrTitle = document.createElement("div");
                    qrTitle.textContent = "QR Code:";
                    qrTitle.style.marginTop = "18px";
                    qrTitle.style.fontWeight = "bold";

                    const img = document.createElement("img");
                    img.src = data.qr_code;
                    img.style.width = "180px";
                    img.style.marginTop = "10px";
                    img.style.background = "white";
                    img.style.padding = "10px";
                    img.style.borderRadius = "12px";

                    result.appendChild(qrTitle);
                    result.appendChild(img);
                }
                
                if (data.valid === true) {
                    badge.innerHTML = '<span class="badge badge-valid">VALID CREDENTIAL</span>';
                } else if (data.valid === false) {
                    badge.innerHTML = '<span class="badge badge-invalid">INVALID CREDENTIAL</span>';
                }
            }

            async function issueCredential() {
                const response = await fetch("/issue", {
                    method: "POST",
                    headers: {"Content-Type": "application/json"},
                    body: JSON.stringify({
                        credential_type: document.getElementById("type").value,
                        name: document.getElementById("name").value,
                        surname: document.getElementById("surname").value,
                        date_of_birth: document.getElementById("dob").value,
                        document_id: document.getElementById("doc").value,
                        expiry: document.getElementById("expiry").value
                    })
                });
    
                const data = await response.json();
                showResult(data);
            }

            async function verifyById() {
                const id = document.getElementById("verifyId").value;
                const response = await fetch("/verify_id/" + id);

                const data = await response.json();
                showResult(data);
            }

            async function createPresentation() {
                const id = document.getElementById("presentationId").value;
                const fields = document.getElementById("fields").value
                    .split(",")
                    .map(field => field.trim());

                const response = await fetch("/presentation/create", {
                    method: "POST",
                    headers: {"Content-Type": "application/json"},
                    body: JSON.stringify({
                        credential_id: id,
                        fields: fields
                    })
                });

                const data = await response.json();
                showResult(data);
            }

            async function revokeCredential() {
                const id = document.getElementById("revokeId").value;

                const response = await fetch("/revoke/" + id, {
                    method: "POST"
                });

                const data = await response.json();
                showResult(data);
            }
            function downloadCredential() {

                const id = document.getElementById("downloadId").value;

                if (!id) {
                    alert("Please enter a credential ID");
                    return;
                }

                window.location.href =
                    "/credential/" + id + "/download";
            }
        </script>
    </body>
    </html>
    """

@app.get("/verify_page/{cred_id}", response_class=HTMLResponse)
def verify_page(cred_id: str):

    cursor.execute("""
    SELECT * FROM credentials
    WHERE id = ?
    """, (cred_id,))

    row = cursor.fetchone()

    if not row:
        return """
        <html>
        <body style="font-family: Arial; padding: 40px;">
            <h1 style="color: #dc2626;">Credential Not Found</h1>
            <p>The credential ID does not exist in the system.</p>
        </body>
        </html>
        """

    credential = {
        "id": row[0],
        "credential_type": row[1],
        "name": row[2],
        "surname": row[3],
        "date_of_birth": row[4],
        "document_id": row[5],
        "expiry": row[6],
        "issued_at": row[7]
    }

    age = calculate_age(credential["date_of_birth"])
    days_remaining = expiry_status(credential["expiry"])
    expiry_message = ""

    if days_remaining < 0:

        expiry_message = (
            f"🔴 Expired {-days_remaining} days ago"
        )

    elif days_remaining <= 30:

        expiry_message = (
            f"⚠ Expires in {days_remaining} days"
        )
    signature_b64 = row[8]
    signature = base64.b64decode(signature_b64)

    is_valid_signature = verify_credential(credential, signature)

    cursor.execute("""
    SELECT * FROM revoked
    WHERE credential_id = ?
    """, (cred_id,))

    revoked_row = cursor.fetchone()
    is_revoked = revoked_row is not None

    expiry_date = datetime.strptime(credential["expiry"], "%Y-%m-%d")
    is_expired = datetime.now() > expiry_date

    final_valid = (
        is_valid_signature
        and not is_revoked
        and not is_expired
    )

    if is_revoked:
        credential_status = "🔴 REVOKED"
        status_color = "#dc2626"

    elif is_expired:
        credential_status = "🟠 EXPIRED"
        status_color = "#f59e0b"

    else:
        credential_status = "🟢 ACTIVE"
        status_color = "#16a34a"

    if final_valid:
        status_text = "Credential Valid"
        status_color = "#16a34a"
        status_icon = "✅"
    else:
        status_text = "Credential Invalid"
        status_color = "#dc2626"
        status_icon = "❌"

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Credential Verification Result</title>
        <style>
            body {{
                margin: 0;
                font-family: Arial, sans-serif;
                background: #eef2f7;
                color: #1f2937;
            }}

            .container {{
                max-width: 750px;
                margin: 60px auto;
                background: white;
                border-radius: 20px;
                padding: 35px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.12);
            }}

            .status {{
                text-align: center;
                color: {status_color};
                font-size: 34px;
                font-weight: bold;
                margin-bottom: 25px;
            }}

            .section {{
                margin-top: 25px;
            }}

            .row {{
                display: flex;
                justify-content: space-between;
                padding: 12px 0;
                border-bottom: 1px solid #e5e7eb;
            }}

            .label {{
                font-weight: bold;
                color: #374151;
            }}

            .value {{
                color: #111827;
            }}

            .badge {{
                display: inline-block;
                padding: 6px 12px;
                border-radius: 999px;
                font-weight: bold;
                font-size: 13px;
            }}

            .green {{
                background: #dcfce7;
                color: #166534;
            }}

            .red {{
                background: #fee2e2;
                color: #991b1b;
            }}

            .footer {{
                margin-top: 30px;
                text-align: center;
                color: #6b7280;
                font-size: 14px;
            }}
        </style>
    </head>

    <body>
        <div class="container">
            <div class="status">
                {status_icon} {status_text}
            </div>
            
            <div style="
                text-align:center;
                margin-top:15px;
                font-size:18px;
                font-weight:bold;
            ">
                {expiry_message}
            </div>
            
            <div style="text-align:center; margin-bottom:25px;">
                <div style="
                    width:110px;
                    height:110px;
                    border-radius:50%;
                    background:#dbeafe;
                    margin:0 auto 12px auto;
                    display:flex;
                    align-items:center;
                    justify-content:center;
                    font-size:50px;
                ">
                    👤
                </div>

                <h2 style="margin:5px 0; color:#111827;">
                    {credential["name"]} {credential["surname"]}
                </h2>

                <p style="margin:0; color:#6b7280; text-transform:uppercase;">
                    {credential["credential_type"]}
                </p>
            </div>
            
            <div style="
                text-align: center;
                margin-top: 25px;
            ">
                <span style="
                    background:{status_color};
                    color:white;
                    padding:10px 20px;
                    border-radius:30px;
                    font-weight:bold;
                    font-size:18px;
                ">
                    {credential_status}
                </span>
            </div>

            <div class="section">
                <div class="row">
                    <span class="label">Name</span>
                    <span class="value">{credential["name"]}</span>
                </div>
                
                <div class="row">
                    <span class="label">Surname</span>
                    <span class="value">{credential["surname"]}</span>
                </div>
                
                <div class="row">
                    <span class="label">Credential Type</span>
                    <span class="value">{credential["credential_type"]}</span>
                </div>
                
                <div class="row">
                    <span class="label">Date of Birth</span>
                    <span class="value">{credential["date_of_birth"]}</span>
                </div>
                
                <div class="row">
                    <span class="label">Age</span>
                    <span class="value">{age}</span>
                </div>

                <div class="row">
                    <span class="label">Document ID</span>
                    <span class="value">{credential["document_id"]}</span>
                </div>

                <div class="row">
                    <span class="label">Expiry</span>
                    <span class="value">{credential["expiry"]}</span>
                </div>

                <div class="row">
                    <span class="label">Issued At</span>
                    <span class="value">{credential["issued_at"]}</span>
                </div>

                <div class="row">
                    <span class="label">Signature Valid</span>
                    <span class="badge {'green' if is_valid_signature else 'red'}">{is_valid_signature}</span>
                </div>

                <div class="row">
                    <span class="label">Revoked</span>
                    <span class="badge {'red' if is_revoked else 'green'}">{is_revoked}</span>
                </div>

                <div class="row">
                    <span class="label">Expired</span>
                    <span class="badge {'red' if is_expired else 'green'}">{is_expired}</span>
                </div>
            </div>

            <div class="footer">
                Digital Identity Verification System — Verifiable Credentials Demo
            </div>
        </div>
    </body>
    </html>
    """
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():

    cursor.execute("SELECT COUNT(*) FROM credentials")
    credentials_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM revoked")
    revoked_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM presentations")
    presentations_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM verification_logs")
    verifications_count = cursor.fetchone()[0]

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>System Dashboard</title>

        <style>

            body {{
                margin: 0;
                font-family: Arial, sans-serif;
                background: #eef2f7;
            }}

            header {{
                background: linear-gradient(135deg,#1e3a8a,#2563eb);
                color: white;
                padding: 30px;
                text-align: center;
            }}

            .container {{
                max-width: 1100px;
                margin: 40px auto;
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(220px,1fr));
                gap: 20px;
            }}

            .card {{
                background: white;
                padding: 25px;
                border-radius: 18px;
                text-align: center;
                box-shadow: 0 10px 25px rgba(0,0,0,0.08);
            }}

            .icon {{
                font-size: 42px;
            }}

            .number {{
                font-size: 40px;
                font-weight: bold;
                color: #2563eb;
                margin-top: 10px;
            }}

            .label {{
                margin-top: 10px;
                color: #6b7280;
                font-size: 16px;
            }}

        </style>
    </head>

    <body>

        <header>
            <h1>Digital Identity Dashboard</h1>
            <p>System Statistics Overview</p>
        </header>

        <div class="container">

            <div class="card">
                <div class="icon">📄</div>
                <div class="number">{credentials_count}</div>
                <div class="label">Credentials Issued</div>
            </div>

            <div class="card">
                <div class="icon">🚫</div>
                <div class="number">{revoked_count}</div>
                <div class="label">Credentials Revoked</div>
            </div>

            <div class="card">
                <div class="icon">🎫</div>
                <div class="number">{presentations_count}</div>
                <div class="label">Presentations Created</div>
            </div>

            <div class="card">
                <div class="icon">🔍</div>
                <div class="number">{verifications_count}</div>
                <div class="label">Verification Attempts</div>
            </div>

        </div>

    </body>
    </html>
    """
@app.get("/credential/{cred_id}/download")
def download_credential(cred_id: str):
    cursor.execute("""
    SELECT id, credential_type, name, surname, date_of_birth, document_id, expiry, issued_at, signature
    FROM credentials
    WHERE id = ?
    """, (cred_id,))

    row = cursor.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Credential not found")

    credential_package = {
        "credential": {
            "id": row[0],
            "credential_type": row[1],
            "name": row[2],
            "surname": row[3],
            "date_of_birth": row[4],
            "document_id": row[5],
            "expiry": row[6],
            "issued_at": row[7]
        },
        "signature": row[8]
    }

    return JSONResponse(
        content=credential_package,
        headers={
            "Content-Disposition": f"attachment; filename=credential_{cred_id}.json"
        }
    )