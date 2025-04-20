import streamlit as st
import json
import os
import base64
import hashlib
from cryptography.fernet import Fernet
from datetime import datetime, timedelta

DATA_FILE = "secure_data.json"
USER_FILE = "users.json"

# Load stored data from JSON file
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

# Save data to JSON file
def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)

# Load users
def load_users():
    if os.path.exists(USER_FILE):
        with open(USER_FILE, "r") as f:
            return json.load(f)
    return {}

# Save users
def save_users(users):
    with open(USER_FILE, "w") as f:
        json.dump(users, f, indent=4)

# PBKDF2 Hashing
def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
    return base64.b64encode(salt + hashed).decode()

def verify_password(password, hashed_value):
    hashed_value_bytes = base64.b64decode(hashed_value.encode())
    salt = hashed_value_bytes[:16]
    stored_hash = hashed_value_bytes[16:]
    new_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
    return new_hash == stored_hash

# Derive Fernet key from passkey
def derive_key(passkey):
    key = hashlib.pbkdf2_hmac("sha256", passkey.encode(), b'salt_key', 100000)
    return base64.urlsafe_b64encode(key)

# Initialize session state
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "username" not in st.session_state:
    st.session_state.username = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = None

# Register
def register():
    st.subheader("📝 Register")
    username = st.text_input("Choose a Username")
    password = st.text_input("Choose a Password", type="password")
    if st.button("Register"):
        users = load_users()
        if username in users:
            st.error("Username already exists.")
        else:
            hashed = hash_password(password)
            users[username] = {"password": hashed}
            save_users(users)
            st.success("✅ Registered successfully! Please login.")

# Login
def login():
    st.subheader("🔐 Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    users = load_users()

    # Lockout check
    if st.session_state.lockout_time:
        if datetime.now() < st.session_state.lockout_time:
            st.warning("⏳ Too many attempts! Try again later.")
            return
        else:
            st.session_state.lockout_time = None
            st.session_state.failed_attempts = 0

    if st.button("Login"):
        if username in users and verify_password(password, users[username]["password"]):
            st.session_state.logged_in = True
            st.session_state.username = username
            st.session_state.failed_attempts = 0
            st.success("✅ Logged in successfully!")
        else:
            st.session_state.failed_attempts += 1
            st.error(f"❌ Invalid credentials! Attempts left: {3 - st.session_state.failed_attempts}")
            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = datetime.now() + timedelta(seconds=30)
                st.warning("🔒 Too many failed attempts. Locked for 30 seconds.")

# Store encrypted data
def store_data():
    st.subheader("📦 Store Encrypted Data")
    text = st.text_area("Enter the text to encrypt:")
    passkey = st.text_input("Enter a passkey for encryption", type="password")

    if st.button("Encrypt & Save"):
        if text and passkey:
            key = derive_key(passkey)
            cipher = Fernet(key)
            encrypted_text = cipher.encrypt(text.encode()).decode()

            data = load_data()
            user_data = data.get(st.session_state.username, [])
            user_data.append(encrypted_text)
            data[st.session_state.username] = user_data
            save_data(data)
            st.success("✅ Data encrypted and saved!")
        else:
            st.error("⚠️ Both fields are required.")

# View stored encrypted data
def view_encrypted():
    st.subheader("🗂️ View Stored Encrypted Data")
    data = load_data()
    user_data = data.get(st.session_state.username, [])

    if not user_data:
        st.info("No data stored.")
    else:
        for idx, entry in enumerate(user_data, 1):
            st.code(entry, language="text")

# Decrypt data
def decrypt_data():
    st.subheader("🔓 Decrypt Data")
    encrypted_text = st.text_area("Paste Encrypted Data:")
    passkey = st.text_input("Enter Passkey", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            try:
                key = derive_key(passkey)
                cipher = Fernet(key)
                decrypted = cipher.decrypt(encrypted_text.encode()).decode()
                st.success(f"✅ Decrypted Text: {decrypted}")
                st.session_state.failed_attempts = 0
            except Exception as e:
                st.session_state.failed_attempts += 1
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"❌ Failed to decrypt. Attempts left: {attempts_left}")
                if st.session_state.failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts! Please login again.")
                    st.session_state.logged_in = False
                    st.session_state.failed_attempts = 0
        else:
            st.error("⚠️ Please fill both fields.")

# Main
st.title("🔐 Secure Data App")

if not st.session_state.logged_in:
    menu = ["Login", "Register"]
    choice = st.sidebar.selectbox("Menu", menu)
    if choice == "Login":
        login()
    elif choice == "Register":
        register()
else:
    menu = ["Store Data", "View Encrypted Data", "Decrypt Data", "Logout"]
    choice = st.sidebar.selectbox("Menu", menu)

    if choice == "Store Data":
        store_data()
    elif choice == "View Encrypted Data":
        view_encrypted()
    elif choice == "Decrypt Data":
        decrypt_data()
    elif choice == "Logout":
        st.session_state.logged_in = False
        st.session_state.username = None
        st.success("👋 Logged out successfully.")
