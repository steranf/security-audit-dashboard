# Security Audit Dashboard - Backend

This is the Python FastAPI backend for the Security Audit Dashboard. It handles audit requests, executes remote scripts via SSH, and manages results.

## Structure

- `app/main.py`: Application entry point and CORS configuration.
- `app/api.py`: API endpoints (`/audit`, `/audit/{id}`).
- `app/audit_runner.py`: Logic to execute remote commands via SSH (Paramiko).
- `app/models.py`: Pydantic data models.
- `app/utils.py`: Helper functions (logging, ID generation).

## Setup

1.  **Create a virtual environment:**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Configuration:**
    - Ensure you have an SSH key (default: `~/.ssh/id_rsa`) that allows access to the target servers.
    - You can set `SSH_KEY_PATH` environment variable to point to a specific key.
    - The backend currently mocks the remote script execution for demonstration purposes. To run a real script, update `REMOTE_SCRIPT_PATH` in `app/audit_runner.py`.

4.  **Run the server:**
    ```bash
    uvicorn app.main:app --reload --port 3000
    ```

## API Endpoints

-   **POST /api/audit**: Start a new audit.
    -   Body: `{ "server": "192.168.1.10", "user": "root", "port": 22, "mode": "json" }`
-   **GET /api/audit/{audit_id}**: Check status and get results.
-   **GET /api/audits**: List all recent audits in memory.
-   **GET /docs**: Swagger UI documentation.

## Notes

-   **Security**: This backend assumes it runs in a trusted environment. SSH keys should be managed securely.
-   **Persistence**: Currently uses in-memory storage (`audit_store`). For production, integrate a database.
