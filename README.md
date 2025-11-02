💰 IBRAHIM’S BHAROSA WALLET
🧾 Secure Digital Wallet with Encryption, Authentication & Logging

IBRAHIM’S BHAROSA WALLET is a secure and user-friendly digital wallet built with Streamlit, SQLite, and cryptographic encryption. It allows users to register, log in securely, manage balances, transfer funds, upload receipts, encrypt personal notes, and view transaction logs — all inside an elegantly designed web app.

🚀 Features
🔐 User Authentication

Secure user registration and login system

Passwords are hashed using bcrypt

Account lock after 5 failed attempts

💳 Wallet Dashboard

Displays real-time balance

Deposit and transfer funds to other users

Audit trail of all actions (login, deposits, transfers, uploads, etc.)

🧠 Encrypted Notes

Users can write private notes

Notes are encrypted and stored using Fernet (AES-256)

Decrypt your last encrypted note with one click

📂 File Uploads

Upload and store receipts in .txt or .pdf format

All uploads saved locally under /uploads

🧾 Activity Logs

Every user action is logged with timestamps

View personal history in the dashboard

💅 Modern UI

Custom CSS with gradient backgrounds, glassmorphism effects, and hover animations

Sidebar navigation and collapsible sections for organized interaction

🛠️ Installation & Setup
1️⃣ Clone the Repository
git clone https://github.com/yourusername/bharosa-wallet.git
cd bharosa-wallet

2️⃣ Create a Virtual Environment
python -m venv venv
venv\Scripts\activate      # (Windows)
# or
source venv/bin/activate   # (Mac/Linux)

3️⃣ Install Dependencies
pip install streamlit sqlite3 bcrypt cryptography

4️⃣ Run the App
streamlit run bharosa_wallet.py

📁 Project Structure
bharosa_wallet/
│
├── bharosa_wallet.py       # Main Streamlit application
├── database.db             # SQLite database (auto-created)
├── uploads/                # Folder for uploaded receipts
├── README.md               # Documentation file
└── requirements.txt        # (optional) Package dependencies

⚙️ Tech Stack
Component	Technology
Frontend	Streamlit
Backend	SQLite
Encryption	Fernet (AES-256)
Hashing	bcrypt
Language	Python 3.x
Logging	SQLite logs with timestamps
🔒 Security Features

AES-256 level encryption for secure note storage

Bcrypt hashing for user passwords

Session-based login tracking

SQL parameterization (protection from SQL injection)

🧑‍💻 Developer

Author: Ibrahim Irfan
Tagline: “Kyun ke humain hai khyaal aapke bharosay ka 💙”
Built with: 🐍 Python | 🔐 Cryptography | 💻 Streamlit

💬 Future Enhancements

Add 2FA (Two-Factor Authentication)

Enable bank API integration for real fund transfers

Add transaction analytics and charts

Deploy to Streamlit Cloud or Heroku
