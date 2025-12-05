import uuid
import logging
import os
from datetime import datetime

# Configure logging
LOG_DIR = "/var/log/security_reports"
# Ensure log directory exists (or use a local fallback for dev)
if not os.path.exists(LOG_DIR):
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
    except PermissionError:
        LOG_DIR = "logs" # Fallback to local logs folder
        os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, "backend.log")),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

def generate_audit_id() -> str:
    """Generates a unique audit ID."""
    return str(uuid.uuid4())

def log_audit_event(audit_id: str, message: str, level: str = "info"):
    """Logs an audit event."""
    log_msg = f"Audit {audit_id}: {message}"
    if level == "info":
        logger.info(log_msg)
    elif level == "error":
        logger.error(log_msg)
    elif level == "warning":
        logger.warning(log_msg)

def parse_json_output(raw_output: str) -> dict:
    """
    Attempts to parse the raw stdout from the script as JSON.
    If the script returns mixed output, this might need more robust parsing logic
    to extract the JSON part.
    """
    import json
    try:
        # Find the first '{' and last '}' to extract JSON if there's noise
        start = raw_output.find('{')
        end = raw_output.rfind('}') + 1
        if start != -1 and end != -1:
            json_str = raw_output[start:end]
            return json.loads(json_str)
        return {"error": "No JSON found in output", "raw": raw_output}
    except json.JSONDecodeError:
        return {"error": "Failed to parse JSON output", "raw": raw_output}

# Placeholder for notification functions
def send_notification(channel: str, message: str):
    """
    Placeholder for sending notifications via Telegram, Slack, Email.
    """
    logger.info(f"Sending {channel} notification: {message}")
    # Implement actual sending logic here
    pass
