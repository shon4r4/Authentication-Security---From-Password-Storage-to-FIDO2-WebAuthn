from flask import Flask, request, jsonify, url_for, session
from flask_sqlalchemy import SQLAlchemy

from fido2.server import Fido2Server
from fido2.utils import websafe_encode, websafe_decode
from fido2.webauthn import RegistrationResponse, AuthenticationResponse, PublicKeyCredentialDescriptor, PublicKeyCredentialRpEntity, AttestedCredentialData
from fido2 import cbor
from argon2 import PasswordHasher
import os, hashlib, hmac, base64, json, pyotp, qrcode, bcrypt

# Configuration
app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///user.db"
app.config["SECRET_KEY"] = "dev-key"
app.config["PEPPER"] = b"SuperSecretPepper123!"
app.config["MAC_KEY"] = b"TopSecretMACKey123!"
app.config["TOTP_VALID_WINDOW"] = 1

# FIDO2 configuration
RP_ID = 'localhost'
RP_NAME = 'D7076'
rp = PublicKeyCredentialRpEntity(id=RP_ID, name=RP_NAME)
server = Fido2Server(rp)

db = SQLAlchemy(app)
ph = PasswordHasher()

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    salt = db.Column(db.String(64), nullable=False)
    pwd_hash = db.Column(db.String(256), nullable=False)
    alg = db.Column(db.String(20), nullable=False, default="sha256")
    mfa_meta = db.Column(db.Text, default=json.dumps({"enabled": False}))

# Helper methods
def hash_password(password: str, alg: str = "sha256"):
    # Per user salt
    salt = os.urandom(16)
    pepper = app.config["PEPPER"]
    p_bytes = password.encode() + pepper

    match alg:
        case "sha256":
            dk = hashlib.sha256(salt + p_bytes).digest()
            return base64.b64encode(salt).decode(), base64.b64encode(dk).decode(), alg
        case "sha3":
            dk = hashlib.sha3_256(salt + p_bytes).digest()
            return base64.b64encode(salt).decode(), base64.b64encode(dk).decode(), alg
        case "bcrypt":
            return "", bcrypt.hashpw(p_bytes, bcrypt.gensalt()).decode(), alg
        case "argon2":
            return "", ph.hash(password + pepper.decode()), alg
        case _:
            raise ValueError("Unknown algorithm")

def verify_password(password: str, salt_b64: str, stored_hash: str, alg: str):
    pepper = app.config["PEPPER"]
    p_bytes = password.encode() + pepper

    match alg:
        case "sha256":
            salt = base64.b64decode(salt_b64)
            dk = hashlib.sha256(salt + p_bytes).digest()
            return base64.b64encode(dk).decode() == stored_hash
        case "sha3":
            salt = base64.b64decode(salt_b64)
            dk = hashlib.sha3_256(salt + p_bytes).digest()
            return base64.b64encode(dk).decode() == stored_hash
        case "bcrypt":
            return bcrypt.checkpw(p_bytes, stored_hash.encode())
        case "argon2":
            try:
                ph.verify(stored_hash, password + pepper.decode())
                return True
            except Exception:
                return False
        case _:
            return False
        
# Generate MAC/HMAC
def sign_response_mac(data: dict):
    key = app.config["MAC_KEY"]
    payload = json.dumps(data, sort_keys=True).encode()

    # sign response with insecure MAC
    mac = hashlib.sha256(key + payload).hexdigest()
    data["mac"] = mac
    
    return data

def sign_response_hmac(data: dict):
    key = app.config["MAC_KEY"]
    payload = json.dumps(data, sort_keys=True).encode()

    mac = hmac.new(key, payload, hashlib.sha256).hexdigest()
    data["mac"] = mac
    
    return data
        
# verify MAC/HMAC
def verify_mac(data: dict):
    mac = data.pop("mac", None)
    key = app.config["MAC_KEY"]
    payload = json.dumps(data, sort_keys=True).encode()
    
    expected_mac = hashlib.sha256(key + payload).hexdigest()
    return expected_mac == mac

def verify_hmac(data: dict):
    mac = data.pop("mac", None)
    key = app.config["MAC_KEY"]
    payload = json.dumps(data, sort_keys=True).encode()

    expected = hmac.new(key, payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(mac, expected)

def load_mfa_meta(user):
    return json.loads(user.mfa_meta or '{"enabled": false}')

def save_mfa_meta(user, meta):
    user.mfa_meta = json.dumps(meta)
    db.session.commit()
        

def generate_qr(otp_uri: any, username: str):
    # Generate QR image
    img = qrcode.make(otp_uri)

    # Save to static path
    static_dir = os.path.join(app.root_path, "static")
    os.makedirs(static_dir, exist_ok=True)
    img_filename = f"mfa_{username}.png"
    img_path = os.path.join(static_dir, img_filename)

    img.save(img_path)

    qr_url = request.host_url.rstrip("/") + url_for("static", filename=img_filename)
    
    return qr_url, img_path

# Routing
@app.route("/register", methods=["POST"])
def register():
    data = request.get_json(force=True)
    username = data.get("username")
    password = data.get("password")
    alg = data.get("alg", "sha256")

    if not username or not password:
        return jsonify(sign_response_hmac({"response": "username and password required"})), 400
    if User.query.filter_by(username=username).first():
        return jsonify(sign_response_hmac({"response": "username already exists"})), 409

    salt_b64, hash_b64, alg_used = hash_password(password, alg)
    user = User(username=username, salt=salt_b64, pwd_hash=hash_b64, alg=alg_used)
    db.session.add(user)
    db.session.commit()

    return jsonify(sign_response_hmac({"response": f"registered using {alg_used}"})), 201

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(force=True)
    username = data.get("username")
    password = data.get("password")

    user = User.query.filter_by(username=username).first()
    if not user or not verify_password(password, user.salt, user.pwd_hash, user.alg):
        return jsonify(sign_response_hmac({"response": "invalid credentials"})), 401

    meta = load_mfa_meta(user)

    # If MFA is enabled, redirect to MFA verify
    if meta.get("enabled"):
        return jsonify({
            "response": "MFA required",
            "mfa": "/mfa/verify",
            "username": user.username
        }), 401

    # Otherwise, login success
    return jsonify(sign_response_hmac({
        "response": f"login success ({user.alg})",
        "mfa_enabled": False
    })), 200

@app.route("/mfa/setup", methods=["POST"])
def mfa_setup():
    data = request.get_json(force=True)
    username = data.get("username")
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    meta = load_mfa_meta(user)

    # Generate new TOTP secret and update meta
    secret = pyotp.random_base32()
    meta.update({
        "enabled": True,
        "method": "TOTP",
        "secret": secret,
        "counter": meta.get("counter", 0)
    })
    save_mfa_meta(user, meta)

    # Create otp auth URI
    otp_uri = pyotp.TOTP(secret).provisioning_uri(
        name=user.username,
        issuer_name="D7076"
    )

    qr_url, img_path = generate_qr(otp_uri, user.username)

    return jsonify({
        "message": "MFA setup successful",
        "secret": secret,
        "otp_uri": otp_uri,
        "qr_url": qr_url,
        "saved_path": img_path
    }), 200

@app.route("/mfa/setup/hotp", methods=["POST"])
def mfa_setup_hotp():
    data = request.get_json(force=True)
    username = data.get("username")
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    meta = load_mfa_meta(user)

    # Generate HOTP secret and initialise counter
    secret = pyotp.random_base32()
    meta.update({
        "enabled": True,
        "method": "HOTP",
        "secret": secret,
        "counter": 0,
        "accepted": 0,
        "failed": 0
    })
    save_mfa_meta(user, meta)

    # Create otp auth URI
    otp_uri = pyotp.HOTP(secret).provisioning_uri(
        name=user.username,
        issuer_name="D7076"
    )

    qr_url, img_path = generate_qr(otp_uri, user.username)

    return jsonify({
        "message": "HOTP setup successful",
        "secret": secret,
        "otp_uri": otp_uri,
        "qr_url": qr_url,
        "saved_path": img_path
    }), 200

@app.route("/mfa/verify", methods=["POST"])
def mfa_verify():
    data = request.get_json(force=True)
    username = data.get("username")
    code = data.get("code")

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    meta = load_mfa_meta(user)
    if not meta.get("enabled"):
        return jsonify({"error": "MFA not enabled"}), 400

    method = meta.get("method")
    secret = meta.get("secret")
    counter = meta.get("counter", 0)
    valid = False

    if method == "TOTP":
        totp = pyotp.TOTP(secret)
        valid = totp.verify(code, valid_window=app.config["TOTP_VALID_WINDOW"])

    elif method == "HOTP":
        hotp = pyotp.HOTP(secret)
        # check current counter
        if hotp.verify(code, counter):
            valid = True
        # check next counter
        elif hotp.verify(code, counter + 1):
            valid = True
            counter += 1
        if valid:
            meta["counter"] = counter + 1

    # Log success/failure
    if valid:
        meta["accepted"] = meta.get("accepted", 0) + 1
    else:
        meta["failed"] = meta.get("failed", 0) + 1
    save_mfa_meta(user, meta)

    if not valid:
        return jsonify(sign_response_hmac({"response": "invalid MFA code"})), 401

    return jsonify(sign_response_hmac({
        "response": f"login success ({user.alg})",
        "mfa_enabled": True
    })), 200

@app.route("/webauthn/register/begin", methods=["POST"])
def webauthn_register_begin():
    data = request.get_json()
    username = data.get("username")
    if not username:
        return jsonify({"error": "Missing username"}), 400

    user = {
        "id": username.encode("utf-8"),
        "name": username,
        "displayName": username,
    }

    # Start registration
    options, state = server.register_begin(user, user_verification="discouraged")
    session["reg_state"] = state

    response = dict(options.public_key)

    return jsonify({"publicKey": response})

@app.route("/webauthn/register/complete", methods=["POST"])
def webauthn_register_complete():
    data = request.get_json()
    username = data.get("username")
    attestation = data.get("attestation")

    if not username or not attestation:
        return jsonify({"error": "Missing data"}), 400

    state = session.get("reg_state")
    if not state:
        return jsonify({"error": "No registration state"}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Pass the whole attestation dict as a single positional argument
    reg_response = RegistrationResponse.from_dict(attestation)
    auth_data = server.register_complete(state, reg_response)

    public_key_bytes = cbor.encode(auth_data.credential_data.public_key)
    
    meta = json.loads(user.mfa_meta or "{}")

    meta.update({
        "webauthn_enabled": True,
        "webauthn_credential_id": websafe_encode(auth_data.credential_data.credential_id),
        "webauthn_public_key": websafe_encode(public_key_bytes),
        "webauthn_credential_data": websafe_encode(auth_data.credential_data),
    })
    user.mfa_meta = json.dumps(meta)
    db.session.commit()

    return jsonify({"status": "ok"})

@app.route("/webauthn/login/begin", methods=["POST"])
def webauthn_login_begin():
    data = request.get_json()
    username = data.get("username")

    if not username:
        return jsonify({"error": "Missing username"}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    meta = json.loads(user.mfa_meta or "{}")
    cred_id_b64 = meta.get("webauthn_credential_id")
    if not cred_id_b64:
        return jsonify({"error": "No WebAuthn credentials"}), 400

    cred_id = websafe_decode(cred_id_b64)
    cred = PublicKeyCredentialDescriptor(id=cred_id, type="public-key")

    auth_data, state = server.authenticate_begin([cred])
    session["auth_state"] = state

    public_key = dict(auth_data.public_key)

    return jsonify({"publicKey": public_key})

@app.route("/webauthn/login/complete", methods=["POST"])
def webauthn_login_complete():
    data = request.get_json()
    username = data.get("username")
    auth_data_dict = data.get("authData")

    if not username or not auth_data_dict:
        return jsonify({"error": "Missing data"}), 400

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "User not found"}), 404
    meta = json.loads(user.mfa_meta or "{}")
    cred_bytes = websafe_decode(meta["webauthn_credential_data"])
    cred = AttestedCredentialData(cred_bytes)

    # Retrieve login state
    state = session.pop("auth_state", None)
    if not state:
        return jsonify({"error": "No login state"}), 400

    # Parse authentication response
    auth_response = AuthenticationResponse.from_dict(auth_data_dict)
    server.authenticate_complete(state, [cred], auth_response)

    user.mfa_meta = json.dumps(meta)
    db.session.commit()

    return jsonify({"status": "ok"})

@app.route("/mac/naive/verify", methods=["POST"])
def mac_verify():
    data = request.json
    if not verify_mac(data):
        return sign_response_mac({"error": "Invalid MAC"}), 400
    return sign_response_mac({"message": "MAC verified"}), 200

@app.route("/mac/hmac/verify", methods=["POST"])
def hmac_verify():
    data = request.json
    if not verify_hmac(data):
        return sign_response_hmac({"error": "Invalid HMAC"}), 400
    return sign_response_hmac({"message": "HMAC verified"}), 200

@app.route("/")
def index():
    return app.send_static_file("index.html")

# Create db table
with app.app_context():
    db.create_all()

# Run application
if __name__ == "__main__":
    app.run(debug=True, threaded=False)
