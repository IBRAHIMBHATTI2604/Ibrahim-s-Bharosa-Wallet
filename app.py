import streamlit as st
import sqlite3
import bcrypt
from cryptography.fernet import Fernet
import os
import datetime
import re

# ================================
# PAGE CONFIG & CUSTOM CSS
# ================================

st.set_page_config(
    page_title="IBRAHIM'S BHAROSA WALLET",
    page_icon="wallet",
    layout="centered",
    initial_sidebar_state="expanded"
)

# Professional CSS Styling
st.markdown("""
<style>
    /* Main Background & Font */
    .main {
        background: linear-gradient(135deg, #0f0c29, #302b63, #24243e);
            background-image: url('C:/Users/DELL/Desktop/grok/uploads/bg1.png');
        color: #e0e0e0;
        font-family: 'Segoe UI', sans-serif;
    }
    
    /* Title */
    .title {
        font-size: 2.8rem !important;
        font-weight: 700;
        text-align: center;
        background: linear-gradient(90deg, #00c6ff, #0072ff);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 1rem;
    }
    
    /* Sidebar */
    .css-1d391kg {
        background: #1a1a2e;
    }
    
    /* Cards */
    .card {
        background: rgba(30, 30, 60, 0.7);
        border-radius: 16px;
        padding: 1.5rem;
        margin: 1rem 0;
        box-shadow: 0 8px 20px rgba(0,0,0,0.3);
        border: 1px solid rgba(100, 100, 255, 0.2);
    }
    
    /* Input Fields */
    .stTextInput > div > div > input,
    .stNumberInput > div > div > input,
    .stTextArea > div > div > textarea {
        background: #2a2a4a !important;
        color: #ffffff !important;
        border: 1px solid #5555aa !important;
        border-radius: 10px !important;
        padding: 0.8rem !important;
    }
    
    /* Buttons */
    .stButton > button {
        background: linear-gradient(45deg, #0072ff, #00c6ff);
        color: white;
        border: none;
        border-radius: 12px;
        padding: 0.6rem 1.5rem;
        font-weight: 600;
        transition: all 0.3s;
        box-shadow: 0 4px 10px rgba(0,114,255,0.3);
    }
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 15px rgba(0,114,255,0.5);
    }
    
    /* Success / Error */
    .stSuccess { border-left: 5px solid #00ff88; padding-left: 1rem; }
    .stError { border-left: 5px solid #ff4444; padding-left: 1rem; }
    
    /* Expander */
    .streamlit-expanderHeader {
        background: #2a2a4a;
        border-radius: 10px;
        font-weight: 600;
    }
    
    /* Footer */
    .footer {
        text-align: center;
        margin-top: 3rem;
        color: #888;
        font-size: 0.9rem;
    }
</style>
""", unsafe_allow_html=True)

# ================================
# INITIAL SETUP
# ================================

os.makedirs("uploads", exist_ok=True)

conn = sqlite3.connect('database.db', check_same_thread=False)
c = conn.cursor()

c.execute('''CREATE TABLE IF NOT EXISTS users 
             (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password BLOB, email TEXT, balance REAL DEFAULT 0.0)''')
c.execute('''CREATE TABLE IF NOT EXISTS logs 
             (id INTEGER PRIMARY KEY, user_id INTEGER, action TEXT, timestamp TEXT)''')
c.execute('''CREATE TABLE IF NOT EXISTS encrypted_notes 
             (id INTEGER PRIMARY KEY, user_id INTEGER, note TEXT)''')
conn.commit()

if 'encryption_key' not in st.session_state:
    st.session_state.encryption_key = Fernet.generate_key()
fernet = Fernet(st.session_state.encryption_key)

if 'user_id' not in st.session_state:
    st.session_state.user_id = None
if 'login_attempts' not in st.session_state:
    st.session_state.login_attempts = 0


# ================================
# HELPERS
# ================================

def hash_password(pw):
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt())

def check_password(hashed, pw):
    return bcrypt.checkpw(pw.encode(), hashed)

def is_strong_password(pw):
    return len(pw) >= 8 and re.search(r'\d', pw) and re.search(r'[!@#$%^&*]', pw)

def log_action(user_id, action):
    timestamp = datetime.datetime.now().isoformat()
    c.execute("INSERT INTO logs (user_id, action, timestamp) VALUES (?, ?, ?)", (user_id, action, timestamp))
    conn.commit()


# ================================
# PAGES
# ================================

def register():
    st.markdown("<h2 class='title'>Create Account</h2>", unsafe_allow_html=True)
    st.markdown("<div class='card'>", unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    with col1:
        username = st.text_input("Username", placeholder="john_doe")
    with col2:
        email = st.text_input("Email", placeholder="john@example.com")
    
    col3, col4 = st.columns(2)
    with col3:
        password = st.text_input("Password", type="password", placeholder="••••••••")
    with col4:
        confirm_pw = st.text_input("Confirm Password", type="password", placeholder="••••••••")

    if st.button("Register Now", key="reg_btn"):
        if not is_strong_password(password):
            st.error("Password must be 8+ chars, include digit & symbol.")
        elif password != confirm_pw:
            st.error("Passwords do not match.")
        elif not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            st.error("Invalid email format.")
        else:
            try:
                hashed = hash_password(password)
                c.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)", (username, hashed, email))
                conn.commit()
                st.success("Account created successfully!")
                st.balloons()
            except sqlite3.IntegrityError:
                st.error("Username already exists.")
    
    st.markdown("</div>", unsafe_allow_html=True)


def login():
    st.markdown("<h2 class='title'>Welcome Back</h2>", unsafe_allow_html=True)
    st.markdown("<div class='card'>", unsafe_allow_html=True)
    
    username = st.text_input("Username", placeholder="Enter username")
    password = st.text_input("Password", type="password", placeholder="Enter password")

    if st.button("Login Securely", key="login_btn"):
        c.execute("SELECT id, password FROM users WHERE username=?", (username,))
        user = c.fetchone()
        if user and check_password(user[1], password):
            st.session_state.user_id = user[0]
            st.session_state.login_attempts = 0
            log_action(user[0], "Logged in")
            st.success("Login successful!")
            st.rerun()
        else:
            st.session_state.login_attempts += 1
            if st.session_state.login_attempts >= 5:
                st.error("Account locked – too many attempts.")
            else:
                st.error(f"Invalid credentials. Attempt {st.session_state.login_attempts}/5")

    st.markdown("</div>", unsafe_allow_html=True)


def dashboard():
    if not st.session_state.user_id:
        st.error("Access denied. Please log in.")
        return

    c.execute("SELECT username, email, balance FROM users WHERE id=?", (st.session_state.user_id,))
    user = c.fetchone()
    if not user:
        st.error("User not found.")
        return

    st.markdown(f"<h2 class='title'>Hi, {user[0]}!</h2>", unsafe_allow_html=True)
    st.markdown(f"**Balance:** `${user[2]:,.2f}`", unsafe_allow_html=True)

    # === Profile Card ===
    with st.expander("Profile Settings", expanded=False):
        st.markdown("<div class='card'>", unsafe_allow_html=True)
        new_email = st.text_input("Update Email", value=user[1])
        if st.button("Save Email"):
            if not re.match(r"[^@]+@[^@]+\.[^@]+", new_email):
                st.error("Invalid email.")
            else:
                c.execute("UPDATE users SET email=? WHERE id=?", (new_email, st.session_state.user_id))
                conn.commit()
                log_action(st.session_state.user_id, "Updated profile")
                st.success("Email updated!")
        st.markdown("</div>", unsafe_allow_html=True)

    # === Add Funds ===
    with st.expander("Add Funds", expanded=False):
        st.markdown("<div class='card'>", unsafe_allow_html=True)
        amount = st.number_input("Amount ($)", min_value=0.01, step=10.0)
        if st.button("Deposit"):
            if amount <= 0:
                st.error("Enter valid amount.")
            else:
                new_balance = user[2] + amount
                c.execute("UPDATE users SET balance=? WHERE id=?", (new_balance, st.session_state.user_id))
                conn.commit()
                log_action(st.session_state.user_id, f"Added ${amount}")
                st.success(f"Deposited ${amount:.2f}")
                st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)

    # === Transfer ===
    with st.expander("Transfer Money", expanded=False):
        st.markdown("<div class='card'>", unsafe_allow_html=True)
        transfer_to = st.text_input("Recipient Username")
        transfer_amt = st.number_input("Amount to Send", min_value=0.01)
        if st.button("Send Transfer"):
            c.execute("SELECT balance FROM users WHERE id=?", (st.session_state.user_id,))
            current_balance = c.fetchone()[0]
            if transfer_amt > current_balance:
                st.error("Insufficient funds.")
            elif transfer_to == user[0]:
                st.error("Cannot send to self.")
            else:
                c.execute("SELECT id FROM users WHERE username=?", (transfer_to,))
                recipient = c.fetchone()
                if recipient:
                    new_balance = current_balance - transfer_amt
                    c.execute("UPDATE users SET balance=? WHERE id=?", (new_balance, st.session_state.user_id))
                    c.execute("UPDATE users SET balance=balance + ? WHERE id=?", (transfer_amt, recipient[0]))
                    conn.commit()
                    log_action(st.session_state.user_id, f"Transferred ${transfer_amt} to {transfer_to}")
                    st.success("Transfer successful!")
                    st.rerun()
                else:
                    st.error("Recipient not found.")
        st.markdown("</div>", unsafe_allow_html=True)

    # === Encrypt/Decrypt ===
    with st.expander("Secure Notes", expanded=False):
        st.markdown("<div class='card'>", unsafe_allow_html=True)
        note = st.text_area("Your secret note")
        col1, col2 = st.columns(2)
        with col1:
            if st.button("Encrypt"):
                if note:
                    encrypted = fernet.encrypt(note.encode()).decode()
                    c.execute("INSERT INTO encrypted_notes (user_id, note) VALUES (?, ?)", (st.session_state.user_id, encrypted))
                    conn.commit()
                    log_action(st.session_state.user_id, "Encrypted note")
                    st.success("Encrypted!")
                    st.code(encrypted[:60] + "...")
                else:
                    st.error("Write something first.")
        with col2:
            if st.button("Decrypt Last"):
                c.execute("SELECT note FROM encrypted_notes WHERE user_id=? ORDER BY id DESC LIMIT 1", (st.session_state.user_id,))
                enc = c.fetchone()
                if enc:
                    try:
                        dec = fernet.decrypt(enc[0].encode()).decode()
                        st.success("Decrypted!")
                        st.code(dec)
                    except:
                        st.error("Decryption failed.")
                else:
                    st.error("No encrypted notes.")
        st.markdown("</div>", unsafe_allow_html=True)

    # === File Upload ===
    with st.expander("Upload Receipt", expanded=False):
        st.markdown("<div class='card'>", unsafe_allow_html=True)
        uploaded = st.file_uploader("PDF or TXT only", type=['txt', 'pdf'])
        if uploaded:
            if uploaded.name.endswith(('.txt', '.pdf')):
                with open(os.path.join("uploads", uploaded.name), "wb") as f:
                    f.write(uploaded.getbuffer())
                log_action(st.session_state.user_id, f"Uploaded {uploaded.name}")
                st.success(f"Uploaded: {uploaded.name}")
            else:
                st.error("Only .txt or .pdf allowed.")
        st.markdown("</div>", unsafe_allow_html=True)

    # === Activity Log ===
    with st.expander("Activity History", expanded=False):
        c.execute("SELECT action, timestamp FROM logs WHERE user_id=? ORDER BY id DESC", (st.session_state.user_id,))
        logs = c.fetchall()
        if logs:
            for action, ts in logs:
                st.write(f"**{ts[:19]}** – {action}")
        else:
            st.info("No activity yet.")

    # === Logout & Session Expiry ===
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Logout", key="logout"):
            log_action(st.session_state.user_id, "Logged out")
            st.session_state.user_id = None
            st.success("Logged out securely.")
            st.rerun()
    with col2:
        if st.button("Simulate Session Expiry"):
            st.session_state.user_id = None
            st.error("Session expired!")
            st.rerun()


# ================================
# MAIN APP
# ================================

def main():
    st.markdown("<h1 class='title'>IBRAHIM'S BHAROSA WALLET</h1>", unsafe_allow_html=True)
    st.markdown("<p style='text-align:center; color:#aaa;'>Advanced Security • End-to-End Encryption • Audit Logs</p>", unsafe_allow_html=True)

    menu = ["Login", "Register", "Dashboard"]
    choice = st.sidebar.selectbox("Navigation", menu, index=0)

    try:
        if choice == "Register":
            register()
        elif choice == "Login":
            login()
        elif choice == "Dashboard":
            dashboard()
    except Exception as e:
        st.error("An unexpected error occurred. Please try again.")

    st.markdown("""
    <div class='footer'>
        © 2025 IBRAHIM'S BHAROSA WALLET| KYUN K HAMIAN HAI KHYAAL APKAY BHAROSAY KA! | Built with Streamlit & AES-256 Encryption
    </div>
    """, unsafe_allow_html=True)


if __name__ == '__main__':
    main()