"""
app.py  —  Secure Messaging Server (True Zero-Knowledge Relay)
==============================================================
A completely blind signaling and relay server for E2EE clients.
The server never decrypts messages, computes shared secrets, or 
holds private key material.
"""
import os
import logging
import base64
from datetime import datetime, timezone

import certifi
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room
from pymongo import MongoClient
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

# ---------------------------------------------------------------------------
# Logging & Setup
# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)-8s %(name)s — %(message)s")
logger = logging.getLogger("app")

app = Flask(__name__)
CORS(app)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "CHANGE_ME_IN_PRODUCTION_USE_ENV_VAR")

# Switched to gevent for stable production WebSocket concurrency
socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading"
)

# ---------------------------------------------------------------------------
# Database Connection
# ---------------------------------------------------------------------------
MONGO_URI = os.environ.get("MONGO_URI", "YOUR_LOCAL_TEST_URI_HERE")

try:
    mongo_client = MongoClient(MONGO_URI, tlsCAFile=certifi.where(), serverSelectionTimeoutMS=5000)
    mongo_client.server_info()
    db = mongo_client.chat_database
    logger.info("✅ MONGODB CONNECTED SUCCESSFULLY")
except Exception as exc:
    logger.critical("❌ MONGODB CONNECTION FAILED: %s", exc)
    raise SystemExit(1) from exc

# Ensure fast lookups
db.users.create_index("phone", unique=True)
db.public_keys.create_index("phone", unique=True)
db.messages.create_index([("sender", 1), ("receiver", 1), ("timestamp", 1)])
db.messages.create_index([("receiver", 1), ("status", 1)])

# Clear ghost sessions on restart
db.users.update_many({}, {"$set": {"online": False, "sid": None}})

# ===========================================================================
# HELPERS
# ===========================================================================
def _now() -> datetime:
    return datetime.now(timezone.utc)

def _pop_otpk(phone: str) -> tuple[str | None, int | None]:
    """Pops one One-Time Prekey from the public pool."""
    doc = db.public_keys.find_one({"phone": phone}, {"oneTimePreKeys": 1})
    if not doc or not doc.get("oneTimePreKeys"):
        return None, None
    
    otpks: list = doc["oneTimePreKeys"]
    if not otpks:
        return None, None
    
    otpk_b64 = otpks[0]
    db.public_keys.update_one({"phone": phone}, {"$pop": {"oneTimePreKeys": -1}})
    return otpk_b64, 0

# ===========================================================================
# HTTP API — AUTH & USERS
# ===========================================================================
@app.route("/", methods=["GET"])
def health_check():
    return jsonify({"status": True, "message": "Blind Relay Server is running."}), 200

@app.route("/signup", methods=["POST"])
def api_signup():
    data = request.get_json(force=True, silent=True) or {}
    phone, password, name = data.get("phone", "").strip(), data.get("password", ""), data.get("name", "").strip()

    if not phone or not password:
        return jsonify({"status": False, "message": "Phone and password are required."}), 400
    if db.users.find_one({"phone": phone}):
        return jsonify({"status": False, "message": "User already exists."}), 409

    user_id = db.users.insert_one({
        "phone": phone, "password": generate_password_hash(password),
        "name": name, "online": False, "sid": None, "created_at": _now(),
    }).inserted_id
    return jsonify({"status": True, "message": "Account created.", "userId": str(user_id)}), 201

@app.route("/login", methods=["POST"])
def api_login():
    data = request.get_json(force=True, silent=True) or {}
    phone, password = data.get("phone", "").strip(), data.get("password", "")

    user = db.users.find_one({"phone": phone})
    if user and check_password_hash(user["password"], password):
        return jsonify({"status": True, "userId": str(user["_id"]), "name": user.get("name")}), 200
    return jsonify({"status": False, "message": "Invalid credentials."}), 401

@app.route("/users", methods=["GET"])
def get_users():
    uid = request.args.get("userId", "")
    query = {"_id": {"$ne": ObjectId(uid)}} if ObjectId.is_valid(uid) else {}
    users = [{"id": str(u["_id"]), "name": u.get("name"), "phone": u.get("phone"), "online": u.get("online", False)} for u in db.users.find(query)]
    return jsonify(users), 200

@app.route("/messages", methods=["GET"])
def get_messages():
    sender, receiver = request.args.get("sender", "").strip(), request.args.get("receiver", "").strip()
    messages = list(db.messages.find({"$or": [{"sender": sender, "receiver": receiver}, {"sender": receiver, "receiver": sender}]}).sort("timestamp", 1))
    
    output = []
    for msg in messages:
        entry = {
            "sender": msg["sender"], "receiver": msg["receiver"],
            "ciphertext": msg.get("ciphertext", ""), "header": msg.get("header", {}),
            "dateTime": msg["timestamp"].isoformat(), "status": msg.get("status", 1),
        }
        if msg.get("alice_ik_pub"):
            entry.update({"alice_ik_pub": msg["alice_ik_pub"], "alice_ek_pub": msg["alice_ek_pub"], "otpk_index": msg.get("otpk_index")})
        output.append(entry)
    return jsonify(output), 200

# ===========================================================================
# HTTP API — PUBLIC KEY DISTRIBUTION
# ===========================================================================
@app.route("/keys/upload", methods=["POST"])
def upload_keys():
    """Client publishes their PUBLIC X3DH key bundle."""
    data = request.get_json(force=True, silent=True) or {}
    phone = data.get("phone", "").strip()
    ik_pub, sign_pub, spk_pub, sig, otpks_pub = data.get("identityKey"), data.get("identitySignKey"), data.get("signedPreKey"), data.get("signature"), data.get("oneTimePreKeys", [])

    if not all([phone, ik_pub, sign_pub, spk_pub, sig]):
        return jsonify({"status": False, "message": "Missing required fields."}), 400

    # Blind Signature Verification
    try:
        sign_key = ed25519.Ed25519PublicKey.from_public_bytes(base64.b64decode(sign_pub))
        sign_key.verify(base64.b64decode(sig), base64.b64decode(spk_pub))
    except InvalidSignature:
        return jsonify({"status": False, "message": "Invalid prekey signature."}), 400

    db.public_keys.update_one({"phone": phone}, {"$set": {
        "identityKey": ik_pub, "identitySignKey": sign_pub, "signedPreKey": spk_pub,
        "signature": sig, "oneTimePreKeys": otpks_pub, "updated_at": _now()
    }}, upsert=True)
    return jsonify({"status": True, "message": "Public Keys stored."}), 200

@app.route("/keys/fetch", methods=["GET"])
def fetch_keys():
    """Alice fetches Bob's public key bundle."""
    target = request.args.get("target_phone", "").strip()
    user_keys = db.public_keys.find_one({"phone": target})
    
    if not user_keys or not user_keys.get("identityKey"):
        return jsonify({"status": False, "message": "No key bundle found."}), 404

    otpk_b64, otpk_index = _pop_otpk(target)
    return jsonify({
        "status": True, "identityKey": user_keys["identityKey"],
        "identitySignKey": user_keys.get("identitySignKey"),
        "signedPreKey": user_keys["signedPreKey"], "signature": user_keys["signature"],
        "oneTimePreKey": otpk_b64, "otpkIndex": otpk_index
    }), 200

# ===========================================================================
# SOCKET.IO — REAL-TIME MESSAGING
# ===========================================================================
@socketio.on("connect")
def handle_connect():
    pass

@socketio.on("disconnect")
def handle_disconnect():
    user = db.users.find_one({"sid": request.sid})
    if user:
        db.users.update_one({"_id": user["_id"]}, {"$set": {"online": False, "sid": None}})

@socketio.on("register")
def handle_register(data):
    phone = data.get("phone", "").strip()
    if not phone: return
    join_room(phone)
    db.users.update_one({"phone": phone}, {"$set": {"online": True, "sid": request.sid}})

    # Deliver offline messages
    pending = list(db.messages.find({"receiver": phone, "status": 1}).sort("timestamp", 1))
    for msg in pending:
        payload = {"msgId": str(msg["_id"]), "sender": msg["sender"], "receiver": msg["receiver"], "ciphertext": msg.get("ciphertext", ""), "header": msg.get("header", {}), "dateTime": msg["timestamp"].isoformat(), "status": 2}
        if msg.get("alice_ik_pub"):
             payload.update({"alice_ik_pub": msg["alice_ik_pub"], "alice_ek_pub": msg["alice_ek_pub"], "otpk_index": msg.get("otpk_index"), "is_session_init": True})
        
        emit("receive_message", payload, room=phone)
        db.messages.update_one({"_id": msg["_id"]}, {"$set": {"status": 2}})
        emit("message_status", {"msgId": str(msg["_id"]), "status": 2}, room=msg["sender"])

@socketio.on("send_message")
def handle_message(data):
    sender, receiver, ciphertext, header = data.get("sender", "").strip(), data.get("receiver", "").strip(), data.get("ciphertext"), data.get("header", {})
    if not sender or not receiver or not ciphertext: return

    msg_doc = {"sender": sender, "receiver": receiver, "ciphertext": ciphertext, "header": header, "timestamp": _now(), "status": 1}
    if data.get("is_session_init"):
        msg_doc.update({"alice_ik_pub": data.get("alice_ik_pub"), "alice_ek_pub": data.get("alice_ek_pub"), "otpk_index": data.get("otpk_index")})

    msg_id = db.messages.insert_one(msg_doc).inserted_id

    # Real-time delivery if online
    receiver_user = db.users.find_one({"phone": receiver})
    payload = {"msgId": str(msg_id), "sender": sender, "receiver": receiver, "ciphertext": ciphertext, "header": header, "dateTime": msg_doc["timestamp"].isoformat(), "status": 2}
    if data.get("is_session_init"):
        payload.update({"alice_ik_pub": msg_doc.get("alice_ik_pub"), "alice_ek_pub": msg_doc.get("alice_ek_pub"), "otpk_index": msg_doc.get("otpk_index"), "is_session_init": True})

    if receiver_user and receiver_user.get("online"):
        emit("receive_message", payload, room=receiver)
        db.messages.update_one({"_id": msg_id}, {"$set": {"status": 2}})
        emit("message_status", {"msgId": str(msg_id), "status": 2}, room=sender)
    else:
        emit("message_status", {"msgId": str(msg_id), "status": 1}, room=sender)

@socketio.on("message_read")
def handle_read(data):
    sender, receiver = data.get("sender", "").strip(), data.get("receiver", "").strip()
    if db.messages.update_many({"sender": sender, "receiver": receiver, "status": {"$lt": 3}}, {"$set": {"status": 3}}).modified_count > 0:
        emit("message_status", {"status": 3}, room=sender)

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
