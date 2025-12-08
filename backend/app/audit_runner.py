
import paramiko
import json
import time
import os
import uuid
import base64
from datetime import datetime
from app.models import AuditRequest, AuditResult, AuditSummary, AuditMetrics, ServiceInfo, Finding, SuspiciousIP, OpenPort
from app.agent_code import AGENT_SCRIPT_CONTENT
# IMPORT THE GENERATOR
from app.utils import generate_html_report, log_audit_event

USE_MOCK = os.getenv("USE_MOCK", "False").lower() == "true"
SSH_KEY_PATH = os.getenv("SSH_KEY_PATH", os.path.expanduser("~/.ssh/id_rsa"))

def mock_audit(request: AuditRequest, audit_id:str, timestamp:str) -> AuditResult:
     return AuditResult(
            id=audit_id, status="completed", server=request.server, timestamp=timestamp,
            summary=AuditSummary(critical=1, warning=2, info=3),
            metrics=AuditMetrics(cpu="10%", ram="1GB/4GB", disk="20%", connections=5),
            services=[ServiceInfo(name="sshd", status="active", version="8.2"), ServiceInfo(name="nginx", status="active", version="1.18")],
            findings=[
                Finding(severity="Critical", description="Mock critical finding", recommendation="Fix immediately", standard_ref="MOCK-CIS-1.1"), 
                Finding(severity="Warning", description="Mock warning", recommendation="Review config", standard_ref="MOCK-OWASP-A1")
            ],
            logs=["mock log 1", "mock log 2"],
            ips=[SuspiciousIP(ip="1.2.3.4", country="Mockland", reason="mock reason")]
        )

def run_audit_task(request: AuditRequest) -> AuditResult:
    audit_id = str(uuid.uuid4())
    timestamp = datetime.now().isoformat()
    if USE_MOCK:
        return mock_audit(request, audit_id, timestamp)
    return _run_ssh_audit(audit_id, timestamp, request)

def _run_ssh_audit(audit_id: str, timestamp: str, request: AuditRequest) -> AuditResult:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    pkey = None
    key_skipped = False
    if os.path.exists(SSH_KEY_PATH):
        try:
            pkey = paramiko.RSAKey.from_private_key_file(SSH_KEY_PATH, password=request.passphrase)
        except paramiko.ssh_exception.PasswordRequiredException:
            # Key is encrypted. Don't block yet. Try other auth methods or fail later.
            pkey = None
            key_skipped = True
        except: 
            try:
                pkey = paramiko.Ed25519Key.from_private_key_file(SSH_KEY_PATH, password=request.passphrase)
            except paramiko.ssh_exception.PasswordRequiredException:
                pkey = None
                key_skipped = True
            except: 
                pkey = None

    try:
        client.connect(request.server, port=request.port, username=request.user, pkey=pkey, password=request.password, timeout=10)
        
        remote_file = f"/tmp/audit_{uuid.uuid4().hex}.py"
        b64_script = base64.b64encode(AGENT_SCRIPT_CONTENT.encode('utf-8')).decode('utf-8')
        client.exec_command(f"echo '{b64_script}' | base64 -d > {remote_file}")

        base_cmd = f"python3 {remote_file}"
        cmd = f"echo '{request.password}' | sudo -S -p '' {base_cmd}" if request.password else f"sudo {base_cmd}"
        
        stdin, stdout, stderr = client.exec_command(cmd, timeout=120)
        exit_code = stdout.channel.recv_exit_status()
        output = stdout.read().decode('utf-8')
        
        client.exec_command(f"rm {remote_file}")
        client.close()

        if exit_code != 0: raise Exception(f"Agent Error: {stderr.read().decode()}")

        data = json.loads(output)
        
        final_result = AuditResult(
            id=audit_id, status="completed", server=request.server, timestamp=timestamp,
            summary=AuditSummary(**data.get("summary", {})),
            metrics=AuditMetrics(**data.get("metrics", {})),
            services=[ServiceInfo(**s) for s in data.get("services", [])],
            findings=[Finding(**f) for f in data.get("findings", [])],
            logs=data.get("logs", []),
            ips=[SuspiciousIP(**i) for i in data.get("ips", [])],
            open_ports=[OpenPort(**p) for p in data.get("open_ports", [])]
        )

        # GENERATE HTML REPORT
        report_path = f"/tmp/audit-report-{audit_id}.html"
        generate_html_report(final_result, filename=report_path)
        
        return final_result

    except Exception as e:
        # Check if this is an Auth failure and we skipped a locked key
        if "Authentication failed" in str(e) or isinstance(e, paramiko.AuthenticationException):
            if key_skipped and not request.passphrase:
                # NOW we know we needed that key
                # Raise specific error that api.py catches
                # We return a dummy result that api.py logic detects via 'status=failed' and findings description
                return AuditResult(
                    id=audit_id, status="failed", server=request.server, timestamp=timestamp,
                    summary=AuditSummary(critical=0,warning=0,info=0), metrics=AuditMetrics(cpu="N/A",ram="N/A",disk="N/A",connections=0),
                    services=[], findings=[Finding(severity="Error", description="PassphraseRequired")], logs=[], ips=[]
                )

        return AuditResult(
            id=audit_id, status="failed", server=request.server, timestamp=timestamp,
            summary=AuditSummary(critical=0,warning=0,info=0), metrics=AuditMetrics(cpu="N/A",ram="N/A",disk="N/A",connections=0),
            services=[], findings=[Finding(severity="Error", description=str(e))], logs=[], ips=[]
        )
