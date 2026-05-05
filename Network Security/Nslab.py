from flask import Flask, jsonify, request
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity
import base64
from flask_cors import CORS

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

rp = PublicKeyCredentialRpEntity(
    id="localhost",
    name="WebAuthn Demo"
)

server = Fido2Server(rp)

credentials_db = {}
state_db = {}


import uuid
import qrcode
from io import BytesIO
from flask import send_file

qr_sessions = {}



# GENERATE QR
# -----------------------------
@app.route("/qr_login")
def qr_login():

    session_id = str(uuid.uuid4())
    qr_sessions[session_id] = {"status": "pending"}

    # URL that phone will open
    qr_url = f"http://192.168.49.1:5000/mobile_auth/{session_id}"

    # Generate QR
    img = qrcode.make(qr_url)
    buf = BytesIO()
    img.save(buf)
    buf.seek(0)

    return send_file(buf, mimetype="image/png")



# MOBILE AUTH PAGE
# -----------------------------
@app.route("/mobile_auth/<session_id>")
def mobile_auth(session_id):

    return f"""
    <h2>Authenticate on Phone</h2>
    <button onclick="startAuth()">Authenticate</button>

    <script>
    async function startAuth() {{

        let res = await fetch("http://192.168.49.1:5000/authenticate");
        let options = await res.json();

        options.challenge = Uint8Array.from(atob(options.challenge.replace(/-/g,'+').replace(/_/g,'/')), c=>c.charCodeAt(0));

        let assertion = await navigator.credentials.get({{
            publicKey: options
        }});

        await fetch("/mobile_auth_complete/{session_id}", {{
            method: "POST"
        }});

        alert("Authenticated!");
    }}
    </script>
    """
    


# MOBILE AUTH COMPLETE
# -----------------------------
@app.route("/mobile_auth_complete/<session_id>", methods=["POST"])
def mobile_auth_complete(session_id):

    qr_sessions[session_id]["status"] = "verified"
    return "OK"



# CHECK STATUS (Laptop polls)
# -----------------------------
@app.route("/qr_status/<session_id>")
def qr_status(session_id):

    return jsonify(qr_sessions.get(session_id, {}))

# FIXED base64url decoder
def b64decode(data):
    data += '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data)

@app.route("/")
def home():
    return "WebAuthn Server Running"



# REGISTER BEGIN
# -----------------------------
@app.route("/register")
def register():

    user = {
        "id": b"hack123",
        "name": "Hacker",
        "displayName": "Admin User"
    }

    registration_data, state = server.register_begin(
        user,
        user_verification="discouraged"
    )

    state_db["register"] = state

    return jsonify(registration_data["publicKey"])



# REGISTER COMPLETE
# -----------------------------
@app.route("/register_complete", methods=["POST"])
def register_complete():

    try:
        data = request.json
        print("Incoming data:", data)

        state = state_db.get("register")
        if not state:
            return jsonify({"error": "No registration state"}), 400

        client_data = b64decode(data["response"]["clientDataJSON"])
        att_obj = b64decode(data["response"]["attestationObject"])
        raw_id = b64decode(data["rawId"])

        # FULL STRUCTURE REQUIRED
        import base64

        credential = {
            "id": data["id"],            # keep as-is
            "rawId": data["rawId"],      # KEEP STRING (NOT BYTES)
            "type": data["type"],
            "response": {
                "clientDataJSON": client_data,
                "attestationObject": att_obj
            }
        }
        
        print("ID:", data["id"])
        print("RAWID:", base64.urlsafe_b64encode(raw_id).decode())

        auth_data = server.register_complete(state, credential)

        credentials_db["user"] = auth_data

        print("Registration SUCCESS")

        return jsonify({"status": "registered successfully"})

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500
    


# AUTHENTICATE BEGIN
# -----------------------------
@app.route("/authenticate")
def authenticate():

    if "user" not in credentials_db:
        return jsonify({
            "error": "User not registered. Please register first."
        }), 400

    creds = [credentials_db["user"].credential_data]

    auth_data, state = server.authenticate_begin(creds)

    state_db["auth"] = state

    return jsonify(auth_data["publicKey"])



# AUTHENTICATE COMPLETE
# -----------------------------
@app.route("/authenticate_complete", methods=["POST"])
def authenticate_complete():

    try:
        data = request.json
        print("Auth incoming:", data)

        state = state_db.get("auth")
        if not state:
            return jsonify({"error": "No auth state"}), 400

        credential = credentials_db["user"]

        client_data = b64decode(data["response"]["clientDataJSON"])
        auth_data = b64decode(data["response"]["authenticatorData"])
        signature = b64decode(data["response"]["signature"])
        raw_id = data["rawId"]   # KEEP STRING

        # NEW STRUCTURE (IMPORTANT)
        assertion = {
            "id": data["id"],
            "rawId": raw_id,
            "type": data["type"],
            "response": {
                "clientDataJSON": client_data,
                "authenticatorData": auth_data,
                "signature": signature
            }
        }

        server.authenticate_complete(
            state,
            [credential.credential_data],
            assertion
        )

        print("AUTH SUCCESS")

        return jsonify({"status": "authentication successful"})

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500
    
    
    
# -----------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)