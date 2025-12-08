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
    
    # --- 1. CORE AUTHENTICATION ---
    
    # Check 1: SSH Root Login
    try:
        if "yes" in run_cmd("grep '^PermitRootLogin' /etc/ssh/sshd_config"):
            findings.append({
                "severity": "Critical", 
                "description": "Root login permitted via SSH",
                "recommendation": "Edit /etc/ssh/sshd_config and set PermitRootLogin no",
                "standard_ref": "CIS 5.2.14"
            })
        else:
            findings.append({
                "severity": "Info", 
                "description": "SSH Root Login is disabled (Good)",
                "recommendation": "Mantain this configuration",
                "standard_ref": "CIS 5.2.14"
            })
    except: pass

    # Check 2: Empty Passwords
    try:
        empty_pw = run_cmd("awk -F: '($2 == \"\" ) {print $1}' /etc/shadow 2>/dev/null") 
        if empty_pw:
             findings.append({
                "severity": "Critical", 
                "description": f"Users with empty passwords found: {empty_pw}",
                "recommendation": "Set passwords for these users or lock their accounts (passwd -l)",
                "standard_ref": "CIS 6.2.1"
            })
        else:
             findings.append({
                "severity": "Info", 
                "description": "No users with empty passwords found",
                "recommendation": "Enforce strong password policies",
                "standard_ref": "CIS 6.2.1"
            })
    except: pass

    # Check 3: UID 0 Backdoors
    try:
        users_uid0 = run_cmd("awk -F: '($3 == 0) {print $1}' /etc/passwd").replace('\n', ' ').strip()
        if users_uid0 != 'root':
             findings.append({
                "severity": "Critical", 
                "description": f"Non-root users with UID 0 found: {users_uid0}",
                "recommendation": "Investigate these users immediately. Only root should have UID 0.",
                "standard_ref": "CIS 6.2.5"
            })
        else:
             findings.append({
                "severity": "Info", 
                "description": "No backdoors found (Only root has UID 0)",
                "recommendation": "Monitor /etc/passwd changes",
                "standard_ref": "CIS 6.2.5"
            })
    except: pass

    # --- 2. NETWORK DEFENSE & PROTOCOLS ---

    # Check 4: Firewall Status
    ufw = run_cmd("ufw status | grep 'Status: active'")
    firewalld = run_cmd("systemctl is-active firewalld")
    iptables = run_cmd("iptables -L | grep 'Chain INPUT'")
    if not (ufw or firewalld == 'active' or iptables):
        findings.append({
            "severity": "High", 
            "description": "No active firewall detected",
            "recommendation": "Enable ufw, firewalld or configure iptables rules immediately",
            "standard_ref": "CIS 3.5.1.1"
        })
    else:
        findings.append({
            "severity": "Info", 
            "description": "Firewall is active (Good)",
            "recommendation": "Regularly review firewall rules",
            "standard_ref": "CIS 3.5.1.1"
        })


    # Check 5: Fail2Ban Deep Audit
    try:
        f2b_status = run_cmd("systemctl is-active fail2ban")
        if f2b_status == "active":
            # Get active jails
            jail_list = run_cmd("fail2ban-client status | grep 'Jail list'").replace('Jail list:', '').strip().replace(',', '')
            # Clean split to avoid empty strings and tree artifacts like '`-', '|-'
            active_jails = [j.strip() for j in jail_list.split() if j.strip() and not j.strip() in ['-', '`-','|-']]
            
            # Detect running services
            services_running = run_cmd("ss -tuln")
            
            missing_jails = []
            if "22" in services_running and not any(j in ['sshd', 'ssh'] for j in active_jails): missing_jails.append("SSH")
            if "21" in services_running and not any(j in ['pure-ftpd', 'vsftpd', 'proftpd', 'ftp'] for j in active_jails): missing_jails.append("FTP")
            # Expanded mail jail detection
            if "587" in services_running and not any(j in ['postfix', 'exim', 'sendmail', 'mail', 'postfix-sasl', 'submission'] for j in active_jails): missing_jails.append("Mail")
            if "143" in services_running and not any(j in ['dovecot'] for j in active_jails): missing_jails.append("Dovecot")
            # Database Check
            if "3306" in services_running and not any(j in ['mysqld-auth', 'mysql', 'mariadb'] for j in active_jails): missing_jails.append("MySQL")

            if missing_jails:
                findings.append({
                    "severity": "Warning", 
                    "description": f"Fail2Ban active. Jails: [{', '.join(active_jails)}]. Missing coverage for: {', '.join(missing_jails)}",
                    "recommendation": "Enable/Configure jails in /etc/fail2ban/jail.local for these services",
                    "standard_ref": "CIS 1.6"
                })
            else:
                findings.append({
                    "severity": "Info", 
                    "description": f"Fail2Ban active protecting: {', '.join(active_jails) or 'configured services'}",
                    "recommendation": "Monitor fail2ban logs",
                    "standard_ref": "CIS 1.6"
                })

            # Web Jails Recommendation (Non-Critical)
            if ("80" in services_running or "443" in services_running) and not any(j in ['apache-auth', 'nginx-http-auth', 'nginx-botsearch', 'apache-badbots'] for j in active_jails):
                 findings.append({
                    "severity": "Info", 
                    "description": "Web Services active. No specific web jails (botsearch/http-auth) detected.",
                    "recommendation": "Consider enabling web-specific jails if hosting dynamic sites or logins."
                })
        else:
             findings.append({
                "severity": "High", 
                "description": "Fail2Ban intrusion detection is NOT active",
                "recommendation": "Install and start fail2ban to prevent brute-force attacks",
                "standard_ref": "CIS 1.6"
            })
    except: pass

    # Check 6: Protocol Security (SSH, FTP)
    try:
        # SSH Protocol Check
        ssh_proto = run_cmd("grep '^Protocol' /etc/ssh/sshd_config | grep '1'")
        if ssh_proto:
            findings.append({"severity": "Critical", "description": "Obsolete SSH Protocol 1 enabled", "recommendation": "Force Protocol 2 in sshd_config", "standard_ref": "CIS 5.2.2"})
        else:
            findings.append({"severity": "Info", "description": "SSH is using secure Protocol 2", "recommendation": "Mantain standard", "standard_ref": "CIS 5.2.2"});

        # FTP Process Check (Smart TLS Detection)
        if "21" in run_cmd("ss -tuln"):
             # 1. Check process arguments for forced TLS
             ftp_process = run_cmd("ps -eo args | grep pure-ftpd")
             # 2. Check config file for TLS directive
             ftp_config = run_cmd("grep '^TLS' /etc/pure-ftpd/pure-ftpd.conf 2>/dev/null")
             
             if "-Y 2" in ftp_process or "-Y 3" in ftp_process or "--tls=2" in ftp_process or "--tls=3" in ftp_process:
                 findings.append({
                    "severity": "Info", 
                    "description": "FTP Service detected with TLS Enforced via process (Good)",
                    "recommendation": "Mantain this secure configuration",
                    "standard_ref": "CIS 2.2.10"
                })
             elif ftp_config:
                 if " 1" in ftp_config:
                      findings.append({
                        "severity": "Warning", 
                        "description": "FTP allows Mixed Mode (TLS 1). Cleartext connections are still permitted.",
                        "recommendation": "Edit /etc/pure-ftpd/pure-ftpd.conf and change to 'TLS 2' to enforce encryption.",
                        "standard_ref": "CIS 2.2.10"
                    })
                 elif " 2" in ftp_config or " 3" in ftp_config:
                      findings.append({
                        "severity": "Info", 
                        "description": f"FTP Service detected with TLS Enforced in config ({ftp_config.strip()})",
                        "recommendation": "Mantain this secure configuration",
                        "standard_ref": "CIS 2.2.10"
                    })
                 else:
                     findings.append({
                        "severity": "Warning", 
                        "description": f"FTP config found but TLS setting is unclear: {ftp_config.strip()}",
                        "recommendation": "Verify pure-ftpd.conf has 'TLS 2'",
                        "standard_ref": "CIS 2.2.10"
                    })
             else:
                 findings.append({
                    "severity": "Warning", 
                    "description": "FTP service detected (Port 21) without clear TLS enforcement.",
                    "recommendation": "Ensure TLS is enforced (e.g., pure-ftpd -Y 2) or check /etc/pure-ftpd.conf",
                    "standard_ref": "CIS 2.2.10"
                })
    except: pass

    # Check 7: Dangerous Ports (Superseded by robust get_open_ports check in main)
    pass

    # --- 3. SYSTEM HEALTH & SECURITY LAYERS ---

    # Check 8: Mandatory Access Control (SELinux/AppArmor)
    try:
        selinux_status = "Disabled"
        if os.path.exists("/usr/sbin/sestatus"):
            selinux_output = run_cmd("sestatus | grep 'Current mode'")
            if "enforcing" in selinux_output.lower(): selinux_status = "Enforcing"
            elif "permissive" in selinux_output.lower(): selinux_status = "Permissive"
        
        apparmor_status = "Inactive"
        if os.path.exists("/usr/sbin/aa-status"):
             if "apparmor module is loaded" in run_cmd("aa-status --enabled 2>&1 || echo 'loaded'"):
                 apparmor_status = "Active"

        if selinux_status == "Enforcing" or apparmor_status == "Active":
            layer = "SELinux" if selinux_status == "Enforcing" else "AppArmor"
            findings.append({
                "severity": "Info", 
                "description": f"Mandatory Access Control is active ({layer})",
                "recommendation": "Mantain checking audit logs",
                "standard_ref": "CIS 1.6.1"
            })
        elif selinux_status == "Permissive":
             findings.append({
                "severity": "Warning", 
                "description": "SELinux is in Permissive mode (Logging only, not blocking)",
                "recommendation": "Set to Enforcing mode for full protection",
                "standard_ref": "CIS 1.6.1"
            })
        else:
            findings.append({
                "severity": "Warning", 
                "description": "No Mandatory Access Control (SELinux/AppArmor) detected/enforced",
                "recommendation": "Enable SELinux or AppArmor for kernel-level defense",
                "standard_ref": "CIS 1.6.1"
            })
    except: pass

    # Check 9: System Updates
    if os.path.exists("/usr/bin/dnf"):
        try:
            out = run_cmd("dnf check-update --security")
            count = sum(1 for line in out.split('\n') if any(arch in line for arch in ['x86_64', 'noarch', 'aarch64']))
            if count > 0:
                findings.append({
                    "severity": "High", 
                    "description": f"{count} critical security updates available",
                    "recommendation": "Run 'dnf update --security' to patch vulnerabilities",
                    "standard_ref": "CIS 1.9"
                })
            else:
                findings.append({
                    "severity": "Info", 
                    "description": "System packages are up to date",
                    "recommendation": "Continue regular patching schedule",
                    "standard_ref": "CIS 1.9"
                })
        except: pass
    elif os.path.exists("/usr/bin/apt"):
        try:
            updates = run_cmd("apt list --upgradable 2>/dev/null | grep -c '-security'")
            if updates and int(updates) > 0:
                 findings.append({
                     "severity": "High", 
                     "description": f"{updates} security updates available",
                     "recommendation": "Run 'apt list --upgradable' and 'apt upgrade' to patch",
                     "standard_ref": "CIS 1.9"
                 })
            else:
                 findings.append({
                     "severity": "Info", 
                     "description": "System packages are up to date",
                     "recommendation": "Continue regular patching schedule",
                     "standard_ref": "CIS 1.9"
                 })
        except: pass

    # Check 10: Resources (CPU/RAM/Disk)
    try:
        disk_use = run_cmd("df / | tail -1 | awk '{print $5}' | tr -d '%'")
        if disk_use and int(disk_use) > 90:
             findings.append({"severity": "Warning", "description": f"Root partition usage is critical: {disk_use}%", "recommendation": "Clean up files"})
        else:
             findings.append({"severity": "Info", "description": f"Disk usage is healthy ({disk_use}%)", "recommendation": "Monitor storage"})

        load = os.getloadavg()[0]
        if load > 4.0:
             findings.append({"severity": "Warning", "description": f"High CPU Load: {load:.2f}", "recommendation": "Check top processes"})
        else:
             findings.append({"severity": "Info", "description": f"CPU Load is normal ({load:.2f})", "recommendation": "Monitor for spikes"})

        with open('/proc/meminfo') as f: meminfo = f.read()
        total = int(re.search(r'MemTotal:\s+(\d+)', meminfo).group(1))
        available = int(re.search(r'MemAvailable:\s+(\d+)', meminfo).group(1))
        used_percent = ((total - available) / total) * 100
        if used_percent > 90:
             findings.append({"severity": "Warning", "description": f"High RAM usage: {used_percent:.1f}%", "recommendation": "Check memory consumers"})
        else:
             findings.append({"severity": "Info", "description": f"RAM usage is healthy ({used_percent:.1f}%)", "recommendation": "Monitor memory"})
    except: pass
    
    # --- 4. SYSTEM HARDENING & INTEGRITY ---

    # Check 11: Kernel Hardening (Sysctl)
    try:
        sysctl_conf = {
            'net.ipv4.conf.all.accept_redirects': {'expected': '0', 'desc': 'ICMP Redirects'},
            'net.ipv4.tcp_syncookies': {'expected': '1', 'desc': 'SYN Flood Protection'},
            'net.ipv4.ip_forward': {'expected': '0', 'desc': 'IP Forwarding'}
        }
        for key, config in sysctl_conf.items():
            val = run_cmd(f"sysctl -n {key}")
            if val != config['expected']:
                findings.append({
                    "severity": "Warning", 
                    "description": f"Kernel parameter '{config['desc']}' is weak ({key}={val})",
                    "recommendation": f"Set '{key} = {config['expected']}' in /etc/sysctl.conf",
                    "standard_ref": "CIS 3.2"
                })
            else:
                 findings.append({
                    "severity": "Info", 
                    "description": f"Kernel Hardening: {config['desc']} is configured correctly",
                    "recommendation": "Maintain kernel security",
                    "standard_ref": "CIS 3.2"
                })
    except: pass

    # Check 12: Critical File Integrity
    try:
        shadow_perms = run_cmd("stat -c '%a %U' /etc/shadow") # e.g., 600 root
        perms = shadow_perms.split()[0]
        owner = shadow_perms.split()[1] if len(shadow_perms.split()) > 1 else 'root'
        
        if int(perms) > 600 or owner != 'root':
             findings.append({
                "severity": "Critical", 
                "description": f"Unsafe permissions on /etc/shadow ({perms} {owner}). Hashes exposed.",
                "recommendation": "Run: chown root:root /etc/shadow && chmod 600 /etc/shadow",
                "standard_ref": "CIS 6.1.2"
            })
        else:
             findings.append({
                "severity": "Info", 
                "description": "/etc/shadow permissions are secure (600/000)",
                "recommendation": "Regularly audit file permissions",
                "standard_ref": "CIS 6.1.2"
            })
    except: pass

    # Check 13: Time Synchronization
    try:
        ntp_status = run_cmd("timedatectl status | grep 'NTP service'") # active / inactive
        if "active" in ntp_status:
             findings.append({
                "severity": "Info", 
                "description": "NTP Time Synchronization is active",
                "recommendation": "Ensure time servers are trusted",
                "standard_ref": "CIS 2.2.1.1"
            })
        else:
             findings.append({
                "severity": "High", 
                "description": "NTP Time Synchronization is NOT active. Logs may be invalid.",
                "recommendation": "Enable chronyd, ntpd, or systemd-timesyncd",
                "standard_ref": "CIS 2.2.1.1"
            })
    except: pass

    #Check 14: Info Leakage & Updates
    try:
        # Reboot Required?
        if os.path.exists("/var/run/reboot-required"):
             findings.append({
                "severity": "Warning", 
                "description": "System requires a reboot (Kernel updates pending)",
                "recommendation": "Reboot system to apply security patches"
            })
        
        # PHP Exposure
        if os.path.exists("/usr/bin/php"):
            expose = run_cmd("php -i | grep 'expose_php'")
            if "On" in expose:
                 findings.append({
                    "severity": "Info", # Info because it's common, but good to fix
                    "description": "PHP is exposing its version (expose_php = On)",
                    "recommendation": "Set 'expose_php = Off' in php.ini to hide version info",
                    "standard_ref": "OWASP INFO"
                })
    except: pass

    # --- 5. ADVANCED THREAT DETECTION ---

    # Check 15: SSH Authorized Keys Audit
    try:
        # Find authorized_keys files
        keys_files = run_cmd("find /home /root -name authorized_keys -maxdepth 3 2>/dev/null").split('\n')
        weak_keys_found = []
        unsafe_perms = []
        
        for kf in keys_files:
            if not kf: continue
            # Check perms
            perms = run_cmd(f"stat -c '%a' {kf}")
            if perms and int(perms) > 600:
                unsafe_perms.append(f"{kf} ({perms})")
            
            # Check content for weak keys (simple heuristic for short RSA)
            # Real audit would need key parsing, but we check for old 1024 bit signatures if possible or just existence
            # For now, let's just check if file exists and is not empty.
            pass 

        if unsafe_perms:
            findings.append({
                "severity": "High", 
                "description": f"Insecure permissions on authorized_keys: {', '.join(unsafe_perms)}",
                "recommendation": "chmod 600 on these files immediately"
            })
        else:
             findings.append({
                "severity": "Info", 
                "description": "SSH authorized_keys permissions are secure",
                "recommendation": "Regularly rotate SSH keys",
                "standard_ref": "CIS 5.2.11"
            })
    except: pass

    # Check 16: Sudoers NOPASSWD
    try:
        # Grep for NOPASSWD but exclude commented lines (starting with #)
        # We search recursively, then pipe to ignore lines where the content part starts with #
        # The output of grep -r is "filename:content", so we ignore if content starts with #
        nopasswd = run_cmd("grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v ':#'")
        
        if nopasswd:
            findings.append({
                "severity": "High", 
                "description": f"Sudoers with NOPASSWD detected: {nopasswd.strip()[:100]}...",
                "recommendation": "Verify if these users really need root without password"
            })
        else:
             findings.append({
                "severity": "Info", 
                "description": "No 'NOPASSWD' directives found in sudoers",
                "recommendation": "Maintain strict sudo controls",
                "standard_ref": "CIS 5.3"
            })
    except: pass

    # Check 17: Suspicious Cron Jobs
    try:
        # Look for suspicious directories in cron files
        cron_suspicious = run_cmd("grep -rE '/tmp/|/var/tmp/|/dev/shm/' /var/spool/cron /etc/cron* 2>/dev/null")
        if cron_suspicious:
            findings.append({
                "severity": "Critical", 
                "description": f"Suspicious Cron Job detected (running from temp dir): {cron_suspicious.strip()}",
                "recommendation": "Investigate immediately! Possible malware persistence."
            })
        else:
             findings.append({
                "severity": "Info", 
                "description": "No suspicious cron jobs detected running from /tmp or /dev/shm",
                "recommendation": "Monitor crontab changes"
            })
    except: pass

    # Check 18: Postfix Open Relay
    try:
        if "25" in services_running or "587" in services_running:
            inet = run_cmd("postconf -h inet_interfaces 2>/dev/null")
            nets = run_cmd("postconf -h mynetworks 2>/dev/null")
            if inet == "all" and (not nets or nets == "0.0.0.0/0"):
                 findings.append({
                    "severity": "Critical", 
                    "description": "Postfix configured as Open Relay (inet=all, networks=open)",
                    "recommendation": "Restrict 'mynetworks' in main.cf immediately",
                    "standard_ref": "CIS 2.2.15"
                })
    except: pass

    # Check 19: Web Security Headers
    try:
        if "80" in services_running or "443" in services_running:
             # Basic curl check
             headers = run_cmd("curl -I -s http://localhost --connect-timeout 2")
             missing_headers = []
             if "X-Frame-Options" not in headers: missing_headers.append("X-Frame-Options")
             if "X-Content-Type-Options" not in headers: missing_headers.append("X-Content-Type-Options")
             
             if missing_headers:
                 findings.append({
                    "severity": "Warning", 
                    "description": f"Missing Web Security Headers: {', '.join(missing_headers)}",
                    "recommendation": "Configure web server to send these headers"
                })
             
             if "Server:" in headers:
                  server_header = [l for l in headers.split('\n') if "Server:" in l][0].strip()
                  findings.append({
                    "severity": "Info", # Just Info, but worth noting
                    "description": f"Web Server exposes version: {server_header}",
                    "recommendation": "Configure 'ServerTokens Prod' (Apache) or 'server_tokens off' (Nginx)"
                })
    except: pass

    # --- 6. DATABASE SECURITY ---
    
    # Check 20: MySQL Data Directory Permissions
    try:
        if "3306" in services_running:
            # Check default data dir /var/lib/mysql
            if os.path.exists("/var/lib/mysql"):
                stat_mysql = run_cmd("stat -c '%a %U' /var/lib/mysql")
                perms = stat_mysql.split()[0]
                owner = stat_mysql.split()[1] if len(stat_mysql.split()) > 1 else 'mysql'
                
                if int(perms) > 700 or owner != 'mysql':
                     findings.append({
                        "severity": "High", 
                        "description": f"Insecure permissions on MySQL Data Dir ({perms} {owner}). Should be 700 mysql.",
                        "recommendation": "chmod 700 /var/lib/mysql && chown mysql:mysql /var/lib/mysql",
                        "standard_ref": "MySQL 3.1"
                    })
                else:
                     findings.append({
                        "severity": "Info", 
                        "description": "MySQL Data Directory permissions are secure (700)",
                        "recommendation": "Maintain strict permissions",
                        "standard_ref": "MySQL 3.1"
                    })
    except: pass

    # Check 21: MySQL Internal Audit (Requires sudo mysql access)
    try:
        mysql_bin = run_cmd("which mysql")
        if "3306" in services_running and mysql_bin:
            # Attempt to connect via sudo (auth_socket)
            # Check local_infile
            local_infile = run_cmd("sudo mysql -e \"SHOW VARIABLES LIKE 'local_infile';\" 2>/dev/null | grep 'local_infile'")
            if local_infile and "ON" in local_infile:
                 findings.append({
                    "severity": "High", 
                    "description": "MySQL 'local_infile' is Enabled. Risk of arbitrary file read/rogue client attacks.",
                    "recommendation": "Set 'local-infile=0' in [mysqld] section of my.cnf",
                    "standard_ref": "MySQL 4.3"
                })
            else:
                 findings.append({
                    "severity": "Info", 
                    "description": "MySQL 'local_infile' is disabled (Secure)",
                    "recommendation": "Maintain secure config",
                    "standard_ref": "MySQL 4.3"
                })
            
            # Check for Anonymous Users or Remote Root
            users_check = run_cmd("sudo mysql -e \"SELECT user,host FROM mysql.user WHERE user='' OR (user='root' AND host='%');\" 2>/dev/null")
            has_issues = False
            if "root" in users_check and "%" in users_check:
                 has_issues = True
                 findings.append({
                    "severity": "Critical", 
                    "description": "MySQL Root user allowed to login remotely ('root'@'%').",
                    "recommendation": "Restrict root to 'localhost' or specific IPs only.",
                    "standard_ref": "MySQL 5.3"
                })
            if "user" in users_check and (not "root" in users_check): 
                 has_issues = True
                 findings.append({
                    "severity": "High", 
                    "description": "MySQL Anonymous Users detected.",
                    "recommendation": "Run 'mysql_secure_installation' to remove anonymous users."
                })
            
            if not has_issues:
                 findings.append({
                    "severity": "Info", 
                    "description": "MySQL User Table is clean (No Anon users, Root is Local)",
                    "recommendation": "Regularly audit user privileges"
                })
            
            # Check 22: MySQL Hygiene (Test DB)
            dbs = run_cmd("sudo mysql -e \"SHOW DATABASES LIKE 'test';\" 2>/dev/null")
            if "test" in dbs:
                 findings.append({
                    "severity": "Warning", 
                    "description": "MySQL 'test' database still exists. Open to all users.",
                    "recommendation": "DROP DATABASE test;"
                })
            else:
                 findings.append({
                    "severity": "Info", 
                    "description": "No insecure 'test' database found",
                    "recommendation": "Maintain clean DB list"
                })
    except: pass

    # MySQL Hygiene Checks (Only if Service is Active)
    if "3306" in services_running:
        # Check 23: MySQL History File presence
        try:
            # Check root and current user history
            history_files = run_cmd("ls -la /root/.mysql_history /home/*/.mysql_history 2>/dev/null")
            if history_files:
                # Check if it points to /dev/null ?
                # Simple check: if file exists and has size > 0, it's a risk
                findings.append({
                    "severity": "Warning", 
                    "description": "MySQL History file detected (~/.mysql_history). May contain cleartext passwords.",
                    "recommendation": "Remove file and link to /dev/null: ln -sf /dev/null ~/.mysql_history"
                })
            else:
                 findings.append({
                    "severity": "Info", 
                    "description": "No unsafe .mysql_history files detected",
                    "recommendation": "Continue using secure auth methods"
                })
        except: pass

        # Check 24: MySQL Log Permissions
        try:
            # Common locations
            log_locs = ["/var/log/mysql/error.log", "/var/log/mysqld.log", "/var/log/mysql/mysql.log"]
            insecure_logs = []
            for log in log_locs:
                if os.path.exists(log):
                    stat = run_cmd(f"stat -c '%a' {log}")
                    if stat and int(stat) > 640:
                        insecure_logs.append(f"{log} ({stat})")
            
            if insecure_logs:
                 findings.append({
                    "severity": "High", 
                    "description": f"Insecure permissions on MySQL Logs: {', '.join(insecure_logs)}",
                    "recommendation": "chmod 640 on log files"
                })
            else:
                 findings.append({
                    "severity": "Info", 
                    "description": "MySQL Log permissions are secure",
                    "recommendation": "Monitor log access"
                })
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

def get_os_version():
    try:
        if os.path.exists("/etc/os-release"):
            with open("/etc/os-release") as f:
                data = {}
                for line in f:
                    if "=" in line:
                        k,v = line.strip().split("=", 1)
                        data[k] = v.strip('"')
                return f"{data.get('NAME', 'Linux')} {data.get('VERSION_ID', '')}".strip()
    except: pass
    return "Unknown Linux"

def get_open_ports():
    ports_data = []
    
    # --- METHOD 1: SS (Preferred) ---
    try:
        raw_out = run_cmd("ss -tulnpe")
        if raw_out:
            lines = raw_out.split('\n')
            if lines and "Netid" in lines[0]: lines = lines[1:] # Skip header
             
            for line in lines:
                parts = line.split()
                if len(parts) < 5: continue
                # ss format: Netid State Recv-Q Send-Q Local_Address:Port Peer_Address:Port [Process]
                
                state = parts[1]
                # Filter: We want listening ports. TCP: LISTEN, UDP: UNCONN
                if state not in ["LISTEN", "UNCONN"]: continue
                
                proto = parts[0]
                local_addr_full = parts[4]
                process_info = ' '.join(parts[6:]) if len(parts) > 6 else "Unknown"
                
                # Parse IP and Port
                ip, port, family = "?", "?", "IPv4"
                if "]:" in local_addr_full: # IPv6
                     ip = local_addr_full.split("]:")[0] + "]"
                     port = local_addr_full.split("]:")[1]
                     family = "IPv6"
                elif ":" in local_addr_full: # IPv4
                     ip = local_addr_full.rsplit(":", 1)[0]
                     port = local_addr_full.rsplit(":", 1)[1]
                     family = "IPv4"
                else:
                     ip = local_addr_full
                
                if ip == "*": ip = "0.0.0.0"

                # Extract Service
                service = "Unknown"
                if 'users:(("' in process_info:
                    try: service = process_info.split('users:(("')[1].split('"')[0]
                    except: pass
                
                # Risk Assessment
                status = "Public" if ip in ["0.0.0.0", "[::]", "*"] else "Local"
                risk = "Low"
                if status == "Public":
                    if port in ["22", "3306", "5432", "6379", "27017", "21", "23"]:
                        risk = "High" if port != "22" else "Medium"
                    elif port in ["80", "443", "25", "465", "587", "110", "143", "993", "995"]:
                        risk = "Low"
                    else:
                        risk = "Medium"
                
                ports_data.append({"proto": proto, "port": port, "ip": ip, "family": family, "service": service, "status": status, "risk": risk})
    except: pass

    # --- METHOD 2: NETSTAT (Fallback) ---
    if not ports_data:
        try:
            raw_out = run_cmd("netstat -tulnpe")
            if raw_out:
                lines = raw_out.split('\n')
                if lines and "Proto" in lines[0]: lines = lines[1:]
                for line in lines:
                    parts = line.split()
                    if len(parts) < 7: continue
                    # Proto Recv-Q Send-Q Local Address ... State ... PID/Prog
                    proto = parts[0]
                    if "tcp" in proto and parts[5] != "LISTEN": continue
                    
                    local_addr = parts[3]
                    ip, port, family = "?", "?", "IPv4"
                    if ":" in local_addr:
                        if "[" in local_addr: # Netstat IPv6 sometimes formatting
                             family = "IPv6"
                        ip = local_addr.rsplit(":", 1)[0]
                        port = local_addr.rsplit(":", 1)[1]
                        # Simple Heuristic for netstat IPv6
                        if "::" in ip: family = "IPv6"
                    else: ip = local_addr
                    
                    process_info = parts[-1]
                    service = process_info.split('/')[1] if "/" in process_info else "Unknown"
                    
                    # Risk (Duplicate logic for robustness)
                    status = "Public" if ip in ["0.0.0.0", "[::]", "*"] else "Local"
                    risk = "Low"
                    if status == "Public":
                        if port in ["22", "3306", "5432", "6379", "27017", "21", "23"]:
                            risk = "High" if port != "22" else "Medium"
                        elif port in ["80", "443", "25", "465", "587", "110", "143", "993", "995"]:
                            risk = "Low"
                        else:
                            risk = "Medium"

                    ports_data.append({"proto": proto, "port": port, "ip": ip, "family": family, "service": service, "status": status, "risk": risk})
        except: pass

    # --- DEBUGGING IF EMPTY ---
    if not ports_data:
        try:
            # Check what SS actually returned
            debug_ss = run_cmd("ss -tulnpe 2>&1")
            debug_netstat = run_cmd("netstat -tulnpe 2>&1")
            user_path = run_cmd("echo $PATH")
            
            ports_data.append({
                "proto": "DEBUG",
                "port": "ERR",
                "ip": "127.0.0.1",
                "family": "IPv4",
                "service": f"SS: {debug_ss[:50]}... PATH: {user_path[:50]}...",
                "status": "Local",
                "risk": "Low"
            })
        except Exception as e:
            ports_data.append({"proto": "ERR", "port": "0", "ip": "0.0.0.0", "family": "IPv4", "service": f"PyCrash: {str(e)}", "status": "Local", "risk": "Low"})

    return ports_data

def main():
    try:
        # 1. Execute all checks
        findings = get_findings()
        open_ports_data = get_open_ports()
        
        # 2. Integrate Open Ports Risks into Findings
        # logic: Deduplicate ports (if port 21 is exposed on IPv4 and IPv6, only report once but mention dual stack if needed)
        seen_ports_risks = set()
        for p in open_ports_data:
            port_key = f"{p['port']}-{p['service']}"
            if port_key in seen_ports_risks: continue
            
            # Check if this port appears multiple times in the data (IPv4 + IPv6) to enhance description
            siblings = [x for x in open_ports_data if f"{x['port']}-{x['service']}" == port_key]
            ips_exposed = list(set([x['ip'] for x in siblings]))
            ip_desc = ", ".join(ips_exposed) if len(ips_exposed) < 3 else "Multiple IPs"

            if p.get('risk') == 'High':
                seen_ports_risks.add(port_key)
                findings.append({
                    "severity": "Critical",
                    "description": f"Port {p['port']} ({p['service']}) is EXPOSED to Public Internet ({ip_desc})",
                    "recommendation": f"Firewall this port or bind {p['service']} to 127.0.0.1 immediately.",
                    "standard_ref": "CIS 3.4"
                })
            elif p.get('risk') == 'Medium':
                seen_ports_risks.add(port_key)
                findings.append({
                    "severity": "Info", 
                    "description": f"Port {p['port']} ({p['service']}) is exposed (Standard/Custom)",
                    "recommendation": "Verify if this service needs to be public.",
                    "standard_ref": "CIS 3.4"
                })
            # Low risk ignored

        # 3. Sort Findings by Severity
        # Severity Order: Critical > High > Warning > Info
        severity_order = {"Critical": 0, "High": 1, "Warning": 2, "Info": 3}
        findings.sort(key=lambda x: severity_order.get(x['severity'], 4))

        result = {
            "hostname": run_cmd("hostname"),
            "os": get_os_version(),
            "ip": get_ips(),
            "findings": findings,
            "services": get_services(),
            "metrics": get_metrics(),
            "logs": get_logs(),
            "open_ports": open_ports_data,
            "summary": {
                "critical": 0,
                "warning": 0,
                "info": 0
            }
        }
        
        for f in result['findings']:
            if f['severity'] == 'Critical': result['summary']['critical'] += 1
            elif f['severity'] == 'High' or f['severity'] == 'Warning': result['summary']['warning'] += 1
            else: result['summary']['info'] += 1
            
        print(json.dumps(result))
    except Exception as e:
        # Fallback in case of severe failure
        print(json.dumps({"error": str(e), "status": "failed"}))

if __name__ == "__main__":
    main()
"""