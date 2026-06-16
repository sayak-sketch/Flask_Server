# Secure E2EE Messaging Server (Zero-Knowledge Relay)

A true "blind" signaling and relay server for an End-to-End Encrypted (E2EE) messaging application. This server facilitates public key exchange and real-time message delivery without ever possessing private key material, decrypting payloads, or computing shared secrets.

This project implements the backend infrastructure necessary to support **X3DH (Extended Triple Diffie-Hellman)** and the **Double Ratchet Algorithm** (Signal Protocol) for secure, asynchronous communication between Web and Android clients.

## 👥 Authors
This project was developed by:
* **Arijeet Das**
* **Ankita Biswas**
* **Rohan Koner**
* **Ritayan Maity**
* **Sayak Mukherjee**

---

## 🏗️ Architecture & Security Model

This server strictly adheres to a **Zero-Knowledge (Blind) Architecture**. 
* **The Server (`app.py`):** Acts purely as a highly efficient post office. It stores user profiles, distributes public X3DH key bundles, buffers opaque ciphertexts for offline users, and routes real-time WebSocket events.
* **The Clients:** All cryptographic heavy lifting—including key generation, computing shared secrets (`x3dh.py`), and encrypting/decrypting messages (`double_ratchet.py`)—happens entirely on the edge devices (Web or Android).
* **Blind Verification:** The server utilizes Ed25519 to blindly verify Signed Prekey (SPK) signatures during upload to prevent malicious key distribution, but it never sees the underlying private X25519 keys.

## ✨ Features
* **X3DH Key Distribution Center:** Stores and serves Identity Keys, Signed Prekeys, and One-Time Prekeys (OTPKs).
* **Real-Time Delivery:** Powered by `Flask-SocketIO` for instant message routing when users are online.
* **Offline Queuing:** Safely queues ciphertexts in MongoDB when the receiver is offline, delivering them immediately upon reconnection.
* **Blind Security:** Zero access to plaintext, session keys, or user private keys.
* **Scalable Concurrency:** Optimized for production using `Gunicorn` and `Eventlet`.

---

## 🛠️ Tech Stack
* **Language:** Python 3.10+
* **Framework:** Flask
* **WebSockets:** Flask-SocketIO
* **Database:** MongoDB (via PyMongo)
* **Cryptography:** `cryptography` library (Ed25519 signature verification)
* **Production Server:** Gunicorn & Eventlet

---

## 🚀 Local Development Setup

### 1. Prerequisites
Ensure you have Python 3 and a MongoDB cluster (e.g., MongoDB Atlas) ready.

### 2. Clone the Repository
```bash
git clone <your-repository-url>
cd <your-repository-folder>