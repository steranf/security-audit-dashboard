import uuid
import logging
import os
import json

LOG_DIR = "/var/log/security_reports"
if not os.path.exists(LOG_DIR):
    try: os.makedirs(LOG_DIR, exist_ok=True)
    except: 
        LOG_DIR = "logs"
        os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(level=logging.INFO, handlers=[logging.FileHandler(os.path.join(LOG_DIR, "backend.log")), logging.StreamHandler()])
logger = logging.getLogger(__name__)

def generate_audit_id() -> str: return str(uuid.uuid4())

def log_audit_event(audit_id: str, message: str, level: str = "info"):
    if level == "info": logger.info(f"Audit {audit_id}: {message}")
    elif level == "error": logger.error(f"Audit {audit_id}: {message}")

def parse_json_output(raw_output: str) -> dict:
    try:
        start, end = raw_output.find('{'), raw_output.rfind('}') + 1
        if start != -1 and end != -1: return json.loads(raw_output[start:end])
        return {"error": "No JSON found", "raw": raw_output}
    except: return {"error": "JSON Parse Error", "raw": raw_output}

def generate_html_report(audit_result, filename=None):
    """Generates a styled HTML report."""
    css = "body{font-family:sans-serif;padding:20px;background:#f4f4f9} .container{background:#fff;padding:30px;border-radius:8px;max-width:1000px;margin:auto} table{width:100%;border-collapse:collapse;margin-top:10px} th,td{padding:10px;border-bottom:1px solid #ddd;text-align:left} .badge{padding:5px;border-radius:4px;color:#fff;font-size:0.8em} .bg-active{background:#27ae60} .bg-critical{background:#c0392b} .bg-high{background:#e67e22} .bg-info{background:#3498db} .metric-box{display:inline-block;width:22%;background:#ecf0f1;padding:15px;margin:1%;text-align:center;border-radius:5px} .val{font-size:1.2em;font-weight:bold;display:block}"
    
    html = f"<html><head><style>{css}</style></head><body><div class='container'><h1>🛡️ Audit Report: {audit_result.server}</h1><p>{audit_result.timestamp}</p>"
    
    # Metrics
    html += f"<h2>📊 Metrics</h2><div><div class='metric-box'><span class='val'>{audit_result.metrics.cpu}</span>CPU</div><div class='metric-box'><span class='val'>{audit_result.metrics.ram}</span>RAM</div><div class='metric-box'><span class='val'>{audit_result.metrics.disk}</span>Disk</div><div class='metric-box'><span class='val'>{audit_result.metrics.connections}</span>Conns</div></div>"
    
    # Services
    html += "<h2>🚀 Services</h2><table><tr><th>Service</th><th>Status</th><th>Version</th></tr>"
    for s in getattr(audit_result, 'services', []) or []:
        html += f"<tr><td><b>{getattr(s,'name','?')}</b></td><td><span class='badge bg-active'>Active</span></td><td>{getattr(s,'version','?')}</td></tr>"
    html += "</table>"
    
    # Findings
    html += "<h2>⚠️ Findings</h2><table><tr><th>Severity</th><th>Description</th></tr>"
    findings = getattr(audit_result, 'findings', []) or []
    if not findings: html += "<tr><td colspan='2'>No findings. Clean!</td></tr>"
    for f in findings:
        sev = getattr(f, 'severity', 'Info')
        cls = 'bg-critical' if sev=='Critical' else 'bg-high' if sev=='High' else 'bg-info'
        html += f"<tr><td><span class='badge {cls}'>{sev}</span></td><td>{getattr(f,'description','')}</td></tr>"
    html += "</table></div></body></html>"

    if filename:
        with open(filename, "w", encoding="utf-8") as f: f.write(html)
    return html
