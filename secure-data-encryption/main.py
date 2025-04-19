import streamlit as st
from cryptography.fernet import Fernet
import hashlib
import json
import os

# ---------- File Names ----------
DATA_FILE = "user_data.json"
ATTEMPT_FILE = "failed_attempts.json"

# ---------- Load/Save JSON ----------
def load_json(file):
    if os.path.exists(file) and os.path.getsize(file) > 0:
        with open(file, "r") as f:
            return json.load(f)
    else:
        return {}


def save_json(data, file):
    with open(file, "w") as f:
        json.dump(data, f, indent=4)

# ---------- Load Data ----------
stored_data = load_json(DATA_FILE)
failed_attempts = load_json(ATTEMPT_FILE)
session_auth = {"authorized": True}

# ---------- Key Setup ----------
if "fernet_key" not in st.session_state:
    st.session_state.fernet_key = Fernet.generate_key()
fernet = Fernet(st.session_state.fernet_key)

# ---------- Hash Function ----------
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# ---------- Insert Data ----------
def insert_data(user_id, text, passkey):
    encrypted_text = fernet.encrypt(text.encode()).decode()
    hashed_passkey = hash_passkey(passkey)
    stored_data[user_id] = {
        "encrypted_text": encrypted_text,
        "passkey": hashed_passkey
    }
    save_json(stored_data, DATA_FILE)
    st.success(f"✅ Data stored securely for user: `{user_id}`")

# ---------- Retrieve Data ----------
def retrieve_data(user_id, passkey):
    if user_id not in stored_data:
        st.error("❌ No data found for this user.")
        return

    if failed_attempts.get(user_id, 0) >= 3:
        session_auth["authorized"] = False
        st.warning("🚫 Too many failed attempts. Login required.")
        st.experimental_rerun()
        return

    hashed_input = hash_passkey(passkey)
    if hashed_input == stored_data[user_id]["passkey"]:
        decrypted = fernet.decrypt(stored_data[user_id]["encrypted_text"].encode()).decode()
        st.success("🔓 Data Decrypted Successfully:")
        st.code(decrypted, language="text")
        failed_attempts[user_id] = 0
    else:
        failed_attempts[user_id] = failed_attempts.get(user_id, 0) + 1
        st.error(f"❌ Incorrect passkey. Attempts left: {3 - failed_attempts[user_id]}")
    
    save_json(failed_attempts, ATTEMPT_FILE)

# ---------- Admin Login ----------
def login_page():
    st.markdown("### 🔐 Admin Login")
    with st.form("admin_login"):
        username = st.text_input("👤 Username")
        password = st.text_input("🔑 Password", type="password")
        submit = st.form_submit_button("Login")

        if submit:
            if username == "admin" and password == "admin123":
                session_auth["authorized"] = True
                failed_attempts.clear()
                save_json(failed_attempts, ATTEMPT_FILE)
                st.success("✅ Login successful!")
            else:
                st.error("❌ Invalid credentials.")

# # ---------- Admin View ----------
# def admin_view():
#     st.markdown("## 🛠️ Admin Data View")
#     col1, col2 = st.columns(2)

#     with col1:
#         st.subheader("📦 Encrypted User Data")
#         if stored_data:
#             st.json(stored_data)
#         else:
#             st.info("No user data found.")

#     with col2:
#         st.subheader("⚠️ Failed Login Attempts")
#         if failed_attempts:
#             st.json(failed_attempts)
#         else:
#             st.info("No failed attempts recorded.")

# ---------- Main App ----------
def main():
    st.set_page_config(page_title="Secure Data Vault", layout="wide")

    st.markdown("""
        <style>
        .block-container {
            padding: 2rem 2rem 2rem 2rem;
        }
        .stTextInput>div>input {
            background-color: #f3f3f3;
        }
        .stTextArea>div>textarea {
            background-color: #f9f9f9;
        }
        </style>
    """, unsafe_allow_html=True)

    st.sidebar.title("🔐 Secure Vault Menu")
    menu = st.sidebar.radio("Navigation", ["🏠 Home", "📥 Insert Data", "🔓 Retrieve Data", "🔑 Admin Login"])

    st.title("🔐 Secure Data Encryption System")
    st.write("Protect and manage sensitive information using encryption.")

    if not session_auth.get("authorized", True) and menu != "🔑 Admin Login":
        st.warning("🔒 You are locked out. Please log in as Admin.")
        login_page()
        return

    if menu == "🏠 Home":
        st.header("📁 Welcome to Your Personal Data Vault")
        st.markdown("Securely encrypt, store, and retrieve data. Choose an action from the sidebar.")

    elif menu == "📥 Insert Data":
        st.header("📥 Store Data Securely")
        with st.form("insert_form"):
            user_id = st.text_input("👤 Enter User ID")
            data = st.text_area("📝 Enter Data to Encrypt")
            passkey = st.text_input("🔑 Create a Passkey", type="password")
            submitted = st.form_submit_button("Store Data")
            if submitted:
                if user_id and data and passkey:
                    insert_data(user_id, data, passkey)
                else:
                    st.warning("⚠️ Please fill all the fields.")

    elif menu == "🔓 Retrieve Data":
        st.header("🔓 Retrieve Your Data")
        with st.form("retrieve_form"):
            user_id = st.text_input("👤 Enter Your User ID")
            passkey = st.text_input("🔑 Enter Your Passkey", type="password")
            submitted = st.form_submit_button("Decrypt Data")
            if submitted:
                if user_id and passkey:
                    retrieve_data(user_id, passkey)
                else:
                    st.warning("⚠️ Please fill in both fields.")

    elif menu == "🔑 Admin Login":
        login_page()

    # elif menu == "🛠️ Admin View":
    #     admin_view()

# ---------- Run ----------
if __name__ == "__main__":
    main()
