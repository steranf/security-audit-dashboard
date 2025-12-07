AGENT_SCRIPT_CONTENT = r"""#!/usr/bin/env python3
import json
import subprocess
import sys
import os
import re
import time

def run_cmd(cmd):
    try:
        return subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL).decode('utf-8').strip()
    except:
        return ""

def get_metrics():
    metrics = {}
    
    # CPU
    try:
        load = os.getloadavg()
        metrics['cpu'] = f"{load[0] * 10:.1f}%" 
    except:
        metrics['cpu'] = "N/A"

    # RAM
    try:
        with open('/proc/meminfo') as f:
            meminfo = f.read()
        total = int(re.search(r'MemTotal:\s+(\d+)', meminfo).group(1))
        available = int(re.search(r'MemAvailable:\s+(\d+)', meminfo).group(1))
        used_gb = (total - available) / 1024 / 1024
        total_gb = total / 1024 / 1024
        metrics['ram'] = f"{used_gb:.1f}GB / {total_gb:.1f}GB"
    except:
        metrics['ram'] = "N/A"

    # Disk
    try:
        df = run_cmd("df -h / | tail -1 | awk '{print $5}'")
        metrics['disk'] = df if df else "N/A"
    except:
        metrics['disk'] = "N/A"

    # Connections
    try:
        conns = run_cmd("ss -tun | wc -l")
        metrics['connections'] = int(conns) if conns else 0
    except:
        metrics['connections'] = 0

    return metrics

def get_services():
    services = []
    # Common services + CyberPanel specific (lscpd, pure-ftpd, dovecot, postfix)
    target_services = [
        'ssh', 'sshd', 
        'nginx', 'httpd', 'apache2', 'lscpd',
        'mysql', 'mariadb', 
        'postfix', 'dovecot', 'pure-ftpd',
        'docker', 'ufw', 'firewalld', 'fail2ban'
    ]
    
    for svc in target_services:
        status = run_cmd(f"systemctl is-active {svc}")
        if status == 'active':
            version = "Unknown"
            # Try to get version
            if svc in ['ssh', 'sshd']:
                v = run_cmd("ssh -V 2>&1")
                version = v.split()[0] if v else "Unknown"
            elif svc == 'nginx':
                v = run_cmd("nginx -v 2>&1")
                version = v.split('/')[-1] if v else "Unknown"
            elif svc == 'lscpd':
                v = run_cmd("/usr/local/lsws/bin/lshttpd -v")
                version = v.split('\n')[0] if v else "Unknown"
            elif svc == 'docker':
                v = run_cmd("docker --version")
                version = v.split('version ')[1].split(',')[0] if v else "Unknown"
            
            services.append({"name": svc, "status": "active", "version": version})
    return services

def get_findings():
    findings = []
    
    # Check Root Login
    try:
        sshd_config = run_cmd("grep '^PermitRootLogin' /etc/ssh/sshd_config")
        if "yes" in sshd_config:
            findings.append({"severity": "Critical", "description": "Root login permitted via SSH"})
    except:
        pass

    # Check Firewall
    ufw = run_cmd("ufw status | grep 'Status: active'")
    firewalld = run_cmd("systemctl is-active firewalld")
    iptables = run_cmd("iptables -L | grep 'Chain INPUT'")
    
    if not (ufw or firewalld == 'active' or iptables):
        findings.append({"severity": "High", "description": "No active firewall detected"})
        
    # Check Updates (yum/dnf for AlmaLinux/CentOS, apt for Debian/Ubuntu)
    if os.path.exists("/usr/bin/dnf"):
        updates = run_cmd("dnf check-update --security | grep -c 'Security'")
        if updates and int(updates) > 0:
             findings.append({"severity": "Medium", "description": f"{updates} security updates available"})
    elif os.path.exists("/usr/bin/apt"):
        updates = run_cmd("apt list --upgradable 2>/dev/null | grep -c 'security'")
        if updates and int(updates) > 0:
             findings.append({"severity": "Medium", "description": f"{updates} security updates available"})

    return findings

def get_logs():
    # Get last 5 logs from relevant files
    logs = []
    # Prioritize mail logs for CyberPanel context, then auth
    log_files = ['/var/log/maillog', '/var/log/mail.log', '/var/log/secure', '/var/log/auth.log']
    
    count = 0
    for log_file in log_files:
        if os.path.exists(log_file):
            try:
                # Get last few lines
                lines = run_cmd(f"tail -n 5 {log_file}").split('\n')
                for l in lines:
                    if l and count < 10:
                        logs.append(f"{log_file}: {l}")
                        count += 1
            except:
                pass
        if count >= 10: break
        
    return logs

def get_ips():
    # Simple netstat parsing for high connection counts
    ips = []
    try:
        # Get top 3 IPs by connection count
        cmd = "ss -tun | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head -3"
        output = run_cmd(cmd)
        for line in output.split('\n'):
            parts = line.strip().split()
            if len(parts) == 2:
                count, ip = parts
                if ip and ip != "Address" and ip != "servers)":
                    ips.append({"ip": ip, "country": "Unknown", "reason": f"{count} connections"})
    except:
        pass
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
    
    # Calc summary
    for f in result['findings']:
        if f['severity'] == 'Critical': result['summary']['critical'] += 1
        elif f['severity'] == 'High': result['summary']['warning'] += 1
        else: result['summary']['info'] += 1

    print(json.dumps(result))

if __name__ == "__main__":
    main()
"""
