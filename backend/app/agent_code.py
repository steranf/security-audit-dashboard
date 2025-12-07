AGENT_SCRIPT_CONTENT = r"""#!/usr/bin/env python3
import json
import subprocess
import sys
import os
import re

# 1. PATH INJECTION: Ensure sbin is visible for sudo
os.environ["PATH"] += os.pathsep + "/usr/local/sbin" + os.pathsep + "/usr/sbin" + os.pathsep + "/sbin" + os.pathsep + "/usr/bin" + os.pathsep + "/bin"

def run_cmd(cmd):
    try:
        # 2. FAULT TOLERANCE: Handle exit codes (e.g. dnf=100) gracefully
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        return result.stdout.decode('utf-8').strip()
    except:
        return ""

def get_metrics():
    metrics = {}
    try:
        load = os.getloadavg()
        metrics['cpu'] = f"{load[0] * 10:.1f}%" 
    except: metrics['cpu'] = "N/A"

    try:
        with open('/proc/meminfo') as f: meminfo = f.read()
        total = int(re.search(r'MemTotal:\s+(\d+)', meminfo).group(1))
        available = int(re.search(r'MemAvailable:\s+(\d+)', meminfo).group(1))
        used_gb = (total - available) / 1024 / 1024
        total_gb = total / 1024 / 1024
        metrics['ram'] = f"{used_gb:.1f}GB / {total_gb:.1f}GB"
    except: metrics['ram'] = "N/A"

    try:
        df = run_cmd("df -h / | tail -1 | awk '{print $5}'")
        metrics['disk'] = df if df else "N/A"
    except: metrics['disk'] = "N/A"

    try:
        conns = run_cmd("ss -tun | wc -l")
        metrics['connections'] = int(conns) if conns else 0
    except: metrics['connections'] = 0
    return metrics

def get_services():
    services = []
    targets = [
        'sshd', 'mariadb', 'mysql', 'postfix', 'dovecot', 'pure-ftpd', 
        'firewalld', 'fail2ban', 'redis', 'clamav-freshclam', 'spamassassin',
        'monarx-agent', 'httpd', 'apache2', 'nginx', 'lscpd', 'lshttpd', 'opendkim'
    ]
    
    cmd_matrix = {
        'mariadb': ['mysqld --version', 'mysql --version'],
        'postfix': ['postconf -d mail_version'],
        'dovecot': ['dovecot --version'],
        'pure-ftpd': ['pure-ftpd --help'], 
        'firewalld': ['firewall-cmd --version'],
        'fail2ban': ['fail2ban-client --version'],
        'redis': ['redis-server --version'],
        'spamassassin': ['spamassassin --version'],
        'clamav-freshclam': ['freshclam --version'],
        'monarx-agent': ['rpm -q monarx-agent', 'dpkg -s monarx-agent'],
        'sshd': ['ssh -V'],
        'nginx': ['nginx -v'],
        'httpd': ['httpd -v', 'apache2 -v'],
        'lscpd': ['/usr/local/lsws/bin/lshttpd -v', 'lshttpd -v'], 
        'lshttpd': ['/usr/local/lsws/bin/lshttpd -v', 'lshttpd -v'],
        'opendkim': ['opendkim -V']
    }

    def extract_version(text):
        if not text: return "Unknown"
        match = re.search(r'(?:Ver:|Ver\s+|Version\s+|v\.|v\s*=?\s*|version\s+)?\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-\w+)?)', text, re.IGNORECASE)
        return match.group(1) if match else text.split('\n')[0][:50].strip()

    for srv in targets:
        try:
            status = run_cmd(f"systemctl is-active {srv}")
            if status != "active" and srv == 'mysql': status = run_cmd("systemctl is-active mariadb")
            
            if status == "active":
                raw_version = ""
                commands = cmd_matrix.get(srv, [f"{srv} --version"])
                for cmd in commands:
                    out = run_cmd(f"{cmd} 2>&1")
                    if out and "command not found" not in out and len(out) > 2:
                        raw_version = out
                        break
                services.append({"name": srv, "status": "active", "version": extract_version(raw_version)})
        except: pass
    return services

def get_findings():
    findings = []
    try:
        if "yes" in run_cmd("grep '^PermitRootLogin' /etc/ssh/sshd_config"):
            findings.append({"severity": "Critical", "description": "Root login permitted via SSH"})
    except: pass

    ufw = run_cmd("ufw status | grep 'Status: active'")
    firewalld = run_cmd("systemctl is-active firewalld")
    iptables = run_cmd("iptables -L | grep 'Chain INPUT'")
    if not (ufw or firewalld == 'active' or iptables):
        findings.append({"severity": "High", "description": "No active firewall detected"})
        
    if os.path.exists("/usr/bin/dnf"):
        try:
            out = run_cmd("dnf check-update --security")
            count = sum(1 for line in out.split('\n') if any(arch in line for arch in ['x86_64', 'noarch', 'aarch64']))
            if count > 0:
                findings.append({"severity": "High", "description": f"{count} critical security updates available"})
        except: pass
    elif os.path.exists("/usr/bin/apt"):
        try:
            updates = run_cmd("apt list --upgradable 2>/dev/null | grep -c '-security'")
            if updates and int(updates) > 0:
                 findings.append({"severity": "High", "description": f"{updates} security updates available"})
        except: pass
    return findings

def get_logs():
    logs = []
    for log_file in ['/var/log/maillog', '/var/log/mail.log', '/var/log/secure', '/var/log/auth.log']:
        if os.path.exists(log_file):
            try:
                lines = run_cmd(f"tail -n 5 {log_file}").split('\n')
                logs.extend([f"{log_file}: {l}" for l in lines if l][:5])
            except: pass
        if len(logs) >= 10: break
    return logs[:10]

def get_ips():
    ips = []
    try:
        output = run_cmd("ss -tun | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head -3")
        for line in output.split('\n'):
            parts = line.strip().split()
            if len(parts) == 2 and parts[1] not in ["Address", "servers)"]:
                ips.append({"ip": parts[1], "country": "Unknown", "reason": f"{parts[0]} connections"})
    except: pass
    return ips

def main():
    result = {
        "summary": {"critical": 0, "warning": 0, "info": 0},
        "metrics": get_metrics(),
        "services": get_services(),
        "findings": get_findings(),
        "logs": get_logs(),
        "ips": get_ips()
    }
    for f in result['findings']:
        if f['severity'] == 'Critical': result['summary']['critical'] += 1
        elif f['severity'] == 'High': result['summary']['warning'] += 1
        else: result['summary']['info'] += 1
    print(json.dumps(result))

if __name__ == "__main__":
    main()
"""