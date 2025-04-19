import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet

# Generate/load encryption key
KEY_FILE = "secret.key"
DATA_FILE = "stored_data.json"

if os.path.exists(KEY_FILE):
    with open(KEY_FILE, "rb") as f:
        KEY = f.read()
else:
    KEY = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(KEY)

cipher = Fernet(KEY)

# Session state initialization
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "is_authorized" not in st.session_state:
    st.session_state.is_authorized = True  # Start unlocked

# Load or initialize JSON data
if os.path.exists(DATA_FILE):
    with open(DATA_FILE, "r") as f:
        stored_data = json.load(f)
else:
    stored_data = {}

# Helper functions
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text, passkey):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)
    entry = stored_data.get(encrypted_text)

    if entry and entry["passkey"] == hashed_passkey:
        st.session_state.failed_attempts = 0
        return cipher.decrypt(encrypted_text.encode()).decode()
    
    st.session_state.failed_attempts += 1
    return None

def save_data():
    with open(DATA_FILE, "w") as f:
        json.dump(stored_data, f, indent=4)

# Streamlit UI
st.title("🔐 Secure Data Encryption System")

menu = ["Home", "Store Data", "View Stored Data", "Decrypt Data","Login"]
choice = st.sidebar.selectbox("Navigation", menu)

# Forced reauthorization after 3 failed attempts
if st.session_state.failed_attempts >= 3 and choice != "Login":
    st.warning("🔒 Too many failed attempts. Reauthorization required!")
    choice = "Login"

if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("Store and retrieve your data securely using a passkey.")

elif choice == "Store Data":
    if st.session_state.is_authorized:
        st.subheader("📂 Store Data Securely")
        user_data = st.text_area("Enter Data:")
        passkey = st.text_input("Enter Passkey:", type="password")

        if st.button("Encrypt & Save"):
            if user_data and passkey:
                hashed = hash_passkey(passkey)
                encrypted = encrypt_data(user_data, passkey)
                stored_data[encrypted] = {"passkey": hashed}
                save_data()
                st.success("✅ Data stored successfully!")
            else:
                st.error("⚠️ Both fields are required!")
    else:
        st.error("❌ You must be authorized to store data.")

elif choice == "View Stored Data":
    st.subheader("📄 Encrypted Data List")
    if stored_data:
        for encrypted_text in stored_data.keys():
            st.code(encrypted_text)
    else:
        st.info("📭 No data stored yet.")

elif choice == "Decrypt Data":
    st.subheader("🔓 Decrypt Your Data")
    encrypted_text = st.text_area("Paste Encrypted Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            result = decrypt_data(encrypted_text, passkey)
            if result:
                st.success(f"✅ Decrypted Data: {result}")
            else:
                st.error(f"❌ Incorrect passkey. Attempts left: {3 - st.session_state.failed_attempts}")
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Login":
    st.subheader("🔐 Reauthorization Required")
    master_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if master_pass == "admin123":  # Replace with secure auth
            st.session_state.failed_attempts = 0
            st.session_state.is_authorized = True
            st.success("✅ Reauthorized!")
        else:
            st.error("❌ Incorrect master password.")
