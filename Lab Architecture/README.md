# 🛡️ SOC Monitoring & SIEM Threat Detection Lab  
## 📦 Full Setup & Installation Guide (End-to-End)

This guide explains how to build the complete enterprise-style SOC lab from scratch including OS setup, tools installation, network configuration, and SIEM integration.

---

# 🖥️ 1. Required Virtualization Platform

Before starting, install a hypervisor.

## 🔹 VirtualBox (Recommended - Free)
https://www.virtualbox.org/wiki/Downloads

OR

## 🔹 VMware Workstation Player
https://www.vmware.com/products/workstation-player.html

---

# 🏗️ 2. Lab Architecture Overview

```
Kali (10.0.1.133) → Load Balancer (10.0.1.139) → Web Servers (10.0.1.137 / 10.0.1.138)
                                                      ↓
                                              Windows Sysmon (10.0.1.132)
                                                      ↓
                                             SIEM Server (Splunk) 10.0.1.142
```

---

# 🐧 3. Kali Linux (Attack Machine)

## 🎯 Role:
Used for attack simulation (Nmap, Hydra, SQLMap, Burp Suite)

## 📥 Download:
https://www.kali.org/get-kali/#kali-virtual-machines

## ⚙️ Setup:
- Import OVA into VirtualBox / VMware
- Assign:
  - RAM: 4GB+
  - CPU: 2 cores
  - Storage: 30GB

## 🔧 Pre-installed Tools:
- Nmap
- Hydra
- SQLMap
- Nikto
- Burp Suite
- Netcat

---

# 🪟 4. Windows 10 Machine (Endpoint + Sysmon)

## 🎯 Role:
Endpoint telemetry, PowerShell monitoring, process tracking

## 📥 Download Windows ISO:
https://www.microsoft.com/software-download/windows10

## ⚙️ Setup:
- Install Windows in VM
- Assign:
  - RAM: 4–8GB
  - CPU: 2–4 cores

---

## 🔍 Install Sysmon (Critical for SOC visibility)

### 📥 Sysmon Download:
https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

### 📥 Sysmon Config (Recommended):
https://github.com/SwiftOnSecurity/sysmon-config

### ⚙️ Install Command:
```powershell
sysmon64.exe -accepteula -i sysmonconfig.xml
```

---

# 📊 5. SIEM Server (Splunk Enterprise)

## 🎯 Role:
Central log collection, detection rules, dashboards

## 📥 Download Splunk:
https://www.splunk.com/en_us/download/splunk-enterprise.html

## ⚙️ Setup:
- Install on Ubuntu or Windows VM
- Access UI:
```
http://localhost:8000
```

## 🔑 Login:
- Username: admin
- Password: (set during installation)

---

## 📡 Install Splunk Universal Forwarder (Important)

### 📥 Download:
https://www.splunk.com/en_us/download/universal-forwarder.html

Used to forward logs from:
- Windows (Sysmon)
- Linux (Apache, NGINX)
- IDS (Suricata)

---

# 🌐 6. Web Servers (Apache)

## 🎯 Role:
Host vulnerable web apps (DVWA)

## 📥 Install:
```bash
sudo apt update
sudo apt install apache2 -y
```

## ▶️ Start Service:
```bash
sudo systemctl start apache2
```

## 📁 Logs Location:
```
/var/log/apache2/access.log
```

---

# 🌐 7. Load Balancer (NGINX)

## 🎯 Role:
Traffic routing between web servers

## 📥 Install:
```bash
sudo apt update
sudo apt install nginx -y
```

## ▶️ Start:
```bash
sudo systemctl start nginx
```

## 📁 Logs:
```
/var/log/nginx/access.log
```

---

# 🛡️ 8. Suricata IDS (Network Detection)

## 🎯 Role:
Detects scans, brute force, SQL injection, reverse shells

## 📥 Install:
```bash
sudo apt update
sudo apt install suricata -y
```

## 📡 Enable Logs:
```
/var/log/suricata/eve.json
```

## 📥 Ruleset:
https://rules.emergingthreats.net/open/suricata-latest.tar.gz

---

# 📡 9. Log Forwarding to Splunk

Install Universal Forwarder on Linux systems.

## ⚙️ inputs.conf example:
```ini
[monitor:///var/log/suricata/eve.json]
index=suricata
sourcetype=suricata

[monitor:///var/log/apache2/access.log]
index=web
sourcetype=apache

[monitor:///var/log/nginx/access.log]
index=web
sourcetype=nginx
```

---

# 🪟 10. Windows Log Forwarding (Sysmon → Splunk)

Enable Windows Event Logs:

- Sysmon Logs
- Security Logs
- System Logs

Forward using Splunk Universal Forwarder.

---

# 🌐 11. Final Lab Network Configuration

## IP Table

| Machine | Role | IP Address |
|--------|------|------------|
| Kali Linux | Attacker | 10.0.1.133 |
| Load Balancer (NGINX) | Reverse Proxy | 10.0.1.139 |
| Web Server 1 | Apache + DVWA | 10.0.1.137 |
| Web Server 2 | Apache + DVWA | 10.0.1.138 |
| Windows Machine | Sysmon Endpoint | 10.0.1.132 |
| SIEM Server | Splunk Enterprise | 10.0.1.142 |

---

# 🔄 12. Attack Simulation Tools

| Tool | Purpose |
|------|--------|
| Nmap | Network scanning |
| Hydra | Brute force |
| SQLMap | SQL injection |
| Burp Suite | Web attacks |
| Netcat | Reverse shell |
| Nikto | Web enumeration |

---

# 🧪 13. Validation Checklist

After setup, verify:

✔ Splunk receives Sysmon logs  
✔ Suricata alerts appear in SIEM  
✔ Apache logs visible in Splunk  
✔ NGINX traffic is tracked  
✔ Kali attacks generate alerts  

---

# 🎯 14. Final Outcome

After full setup you will have:

- Enterprise SOC simulation environment  
- Multi-source SIEM (Splunk)  
- Endpoint detection (Sysmon)  
- Network IDS (Suricata)  
- Web attack detection system  
- Real-time threat monitoring  
- MITRE ATT&CK mapping capability  

---

# 🏆 Skills Demonstrated

- SIEM Engineering  
- Detection Engineering  
- SOC Operations  
- Threat Hunting  
- Incident Monitoring  
- Log Correlation  
- Blue Team Security  

---
