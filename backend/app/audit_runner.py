import paramiko
import json
import time
import os
import uuid
import base64
from datetime import datetime
from app.models import AuditRequest, AuditResult, AuditSummary, AuditMetrics, ServiceInfo, Finding, SuspiciousIP
from app.agent_code import AGENT_SCRIPT_CONTENT

# Environment Configuration
USE_MOCK = os.getenv("USE_MOCK", "True").lower() == "true"
SSH_KEY_PATH = os.getenv("SSH_KEY_PATH", os.path.expanduser("~/.ssh/id_rsa"))

def run_audit_task(request: AuditRequest) -> AuditResult:
    """
    Blocking function to run the audit. 
    Designed to be run in a separate thread via loop.run_in_executor.
    """
    audit_id = str(uuid.uuid4())
    timestamp = datetime.now().isoformat()

    if USE_MOCK:
        return _run_mock_audit(audit_id, timestamp, request)
    
    return _run_ssh_audit(audit_id, timestamp, request)

def _run_mock_audit(audit_id: str, timestamp: str, request: AuditRequest) -> AuditResult:
    """Simulates a remote audit with a delay."""
    time.sleep(2) # Simulate network latency
    
    # Mock Data matching the frontend structure
    return AuditResult(
        id=audit_id,
        status="completed",
        server=request.server,
        timestamp=timestamp,
        summary=AuditSummary(critical=1, warning=3, info=5),
        metrics=AuditMetrics(cpu="15%", ram="4.2GB / 16GB", disk="45% used", connections=23),
        services=[
            ServiceInfo(name="SSH", status="active", version="OpenSSH_8.2p1"),
            ServiceInfo(name="Nginx", status="active", version="1.18.0"),
            ServiceInfo(name="Fail2Ban", status="active", version="0.11.1")
        ],
        findings=[
            Finding(severity="Critical", description="Root login enabled via SSH"),
            Finding(severity="Warning", description="UFW allowing port 8080"),
            Finding(severity="Info", description="System uptime: 14 days")
        ],
        logs=[
            "Dec 05 10:00:01 server systemd[1]: Started Session 1 of user root.",
            "Dec 05 10:05:23 server sshd[1234]: Failed password for invalid user admin",
            "Dec 05 10:10:00 server CRON[5678]: (root) CMD (cd / && run-parts --report)"
        ],
        ips=[
            SuspiciousIP(ip="192.168.1.50", country="Unknown", reason="Failed SSH login"),
            SuspiciousIP(ip="10.0.0.5", country="Local", reason="High traffic")
        ]
    )

def _run_ssh_audit(audit_id: str, timestamp: str, request: AuditRequest) -> AuditResult:
    """
    Executes the audit via SSH using Paramiko with Universal Auth Support (RSA/Ed25519) and Auto-Deploy.
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    pkey = None
    
    # 1. Try to load SSH Key (if exists)
    if os.path.exists(SSH_KEY_PATH):
        # Attempt 1: RSA Key
        try:
            pkey = paramiko.RSAKey.from_private_key_file(SSH_KEY_PATH, password=request.passphrase)
        except paramiko.PasswordRequiredException:
            if not request.passphrase:
                raise Exception("PassphraseRequired")
            raise Exception("Invalid Passphrase for SSH Key")
        except paramiko.SSHException:
            # Attempt 2: Ed25519 Key (Fallback)
            try:
                pkey = paramiko.Ed25519Key.from_private_key_file(SSH_KEY_PATH, password=request.passphrase)
            except paramiko.PasswordRequiredException:
                if not request.passphrase:
                    raise Exception("PassphraseRequired")
                raise Exception("Invalid Passphrase for SSH Key")
            except paramiko.SSHException:
                # Both failed, log and fallback to password auth (pkey=None)
                print(f"Failed to load SSH key from {SSH_KEY_PATH} (tried RSA and Ed25519). Trying password auth if provided.")
                pkey = None

    try:
        # 2. Connect
        client.connect(
            hostname=request.server,
            port=request.port,
            username=request.user,
            pkey=pkey, 
            password=request.password,
            timeout=10,
            look_for_keys=False
        )

        # 3. Auto-Deploy Agent
        remote_filename = f"/tmp/audit_{uuid.uuid4().hex}.py"
        
        try:
            # Attempt A: SFTP
            sftp = client.open_sftp()
            with sftp.file(remote_filename, 'w') as f:
                f.write(AGENT_SCRIPT_CONTENT)
            sftp.close()
        except Exception as e:
            # Attempt B: Fallback to Base64 Echo
            print(f"SFTP failed ({e}), trying Base64 injection...")
            b64_script = base64.b64encode(AGENT_SCRIPT_CONTENT.encode('utf-8')).decode('utf-8')
            cmd_upload = f"echo '{b64_script}' | base64 -d > {remote_filename}"
            stdin, stdout, stderr = client.exec_command(cmd_upload)
            exit_status = stdout.channel.recv_exit_status()
            if exit_status != 0:
                raise Exception(f"Failed to upload agent via Base64: {stderr.read().decode()}")

        try:
            # 4. Execute Agent
            base_cmd = f"python3 {remote_filename}"
            
            # Add flags based on options
            if request.options:
                if request.options.fast:
                    base_cmd += " --fast"
                if request.options.silent:
                    base_cmd += " --silent"

            # Construct final command with Sudo handling
            # Construct final command with Sudo handling
            if request.password:
                # Inject password via stdin for sudo -S
                # Basic escaping for single quotes to prevent shell syntax errors
                safe_password = request.password.replace("'", "'\\''")
                cmd = f"echo '{safe_password}' | sudo -S -p '' {base_cmd}"
            else:
                # Standard execution (relies on passwordless sudo or agent running as root)
                cmd = f"sudo {base_cmd}"

            stdin, stdout, stderr = client.exec_command(cmd, timeout=60)
            
            exit_status = stdout.channel.recv_exit_status()
            output_str = stdout.read().decode('utf-8')
            error_str = stderr.read().decode('utf-8')

            if exit_status != 0:
                raise Exception(f"Script failed (Exit {exit_status}): {error_str}")

            # Parse JSON output
            try:
                data = json.loads(output_str)
                return AuditResult(
                    id=audit_id,
                    status="completed",
                    server=request.server,
                    timestamp=timestamp,
                    summary=AuditSummary(**data.get("summary", {})),
                    metrics=AuditMetrics(**data.get("metrics", {})),
                    services=[ServiceInfo(**s) for s in data.get("services", [])],
                    findings=[Finding(**f) for f in data.get("findings", [])],
                    logs=data.get("logs", []),
                    ips=[SuspiciousIP(**i) for i in data.get("ips", [])],
                    raw_output=output_str
                )
            except json.JSONDecodeError:
                raise Exception("Failed to parse script output as JSON.")

        finally:
            # 5. Cleanup
            try:
                client.exec_command(f"rm {remote_filename}")
            except:
                pass 

    except Exception as e:
        error_msg = str(e)
        if error_msg == "PassphraseRequired":
             pass 

        return AuditResult(
            id=audit_id,
            status="failed",
            server=request.server,
            timestamp=timestamp,
            summary=AuditSummary(critical=0, warning=0, info=0),
            metrics=AuditMetrics(cpu="N/A", ram="N/A", disk="N/A", connections=0),
            services=[],
            findings=[Finding(severity="Error", description=error_msg)],
            logs=[],
            ips=[]
        )
