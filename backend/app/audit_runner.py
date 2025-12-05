import paramiko
import json
import time
import os
import uuid
from datetime import datetime
from app.models import AuditRequest, AuditResult, AuditSummary, AuditMetrics, ServiceInfo, Finding, SuspiciousIP

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
    Executes the audit via SSH using Paramiko.
    """
    client = paramiko.SSHClient()
    # WARNING: AutoAddPolicy is used here for ease of setup. 
    # In strict production environments, known_hosts should be managed explicitly.
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=request.server,
            port=request.port,
            username=request.user,
            key_filename=SSH_KEY_PATH,
            timeout=10
        )

        # Construct command
        # This assumes a script exists on the remote server that outputs JSON
        # In a real deployment, you might SCP the script over first.
        cmd = "/usr/local/bin/security_audit.sh --json" 
        
        # Add flags based on options
        if request.options:
            if request.options.fast:
                cmd += " --fast"
            if request.options.silent:
                cmd += " --silent"

        stdin, stdout, stderr = client.exec_command(cmd, timeout=60)
        
        exit_status = stdout.channel.recv_exit_status()
        output_str = stdout.read().decode('utf-8')
        error_str = stderr.read().decode('utf-8')
        
        client.close()

        if exit_status != 0:
            raise Exception(f"Script failed (Exit {exit_status}): {error_str}")

        # Parse JSON output from the script
        try:
            # We assume the script outputs ONLY valid JSON in stdout
            data = json.loads(output_str)
            
            # Map raw JSON to Pydantic Models
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
            raise Exception("Failed to parse script output as JSON. Ensure script returns valid JSON.")

    except Exception as e:
        # Return a failed result structure
        return AuditResult(
            id=audit_id,
            status="failed",
            server=request.server,
            timestamp=timestamp,
            summary=AuditSummary(critical=0, warning=0, info=0),
            metrics=AuditMetrics(cpu="N/A", ram="N/A", disk="N/A"),
            services=[],
            findings=[Finding(severity="Error", description=str(e))],
            logs=[],
            ips=[]
        )
