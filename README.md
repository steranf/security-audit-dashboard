# 🛡️ Security Audit Dashboard

**Agentless Linux Server Security Auditor**

A professional, lightweight dashboard to audit Linux servers via SSH without installing agents. Generates detailed HTML/JSON reports on services, security findings, and server metrics.

![Dashboard Preview](frontend/src/assets/preview_placeholder.png)

## ✨ Key Features

*   **🕵️ Agentless Auditing**: Connects via SSH (Paramiko), runs a temporary Python script, and disconnects. Zero footprint left on the target server.
*   **🧠 Smart Authentication**: 
    *   Supports SSH Keys (Encrypted & Plain), Password Auth, and Custom Ports.
    *   **Intelligent Fallback**: Can detect locked keys and skip them if a password is provided.
    *   **Sudo Handling**: Prompts for sudo password *only* when the server requires it.
*   **📊 Rich Reporting**:
    *   **Interactive UI**: Built with React + TailwindCSS + Lucide Icons.
    *   **Export Options**: Download professional **HTML Reports**, CSV summaries, or Raw JSON data.
*   **🚀 Modern Stack**:
    *   **Backend**: FastAPI (Python), Async SSH, SQLite.
    *   **Frontend**: Vite (React), TailwindCSS.

---

## 🚀 Quick Start

### Prerequisites
*   Python 3.8+
*   Node.js 16+
*   SSH Key (Optional but recommended)

### 1. Backend Setup

```bash
cd backend
python -m venv venv
# Windows
venv\Scripts\activate
# Linux/Mac
source venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --reload --port 3000
```

### 2. Frontend Setup

```bash
cd frontend
npm install
npm run dev
```

Open your browser at `http://localhost:5173`.

---

## 🛠️ Usage

1.  **Enter Connection Details**: Server IP, User, Port (Default 22).
2.  **Authentication**:
    *   If using an **SSH Key**, ensure it's in the default path (or set `SSH_KEY_PATH` env var).
    *   If the key has a passphrase, the UI will prompt you.
    *   If relying on **Password**, just enter it in the secured field.
3.  **Run Audit**: Click "Start Audit".
4.  **View & Export**: check the results card and click **PDF / HTML** buttons to export.

---

## 🔒 Security Note

*   This tool runs `sudo` commands to fetch system stats (netstat, systemctl, logs).
*   Credentials are sent over encrypted HTTPs (if configured) or localhost, and are **never stored** permanently.
*   The agent script runs in RAM and is deleted immediately after execution.

## 📄 License

MIT License.
