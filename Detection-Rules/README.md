# 🛡️ SOC Monitoring & SIEM Threat Detection Lab

<div align="center">

![SOC Lab](https://img.shields.io/badge/Project-SOC%20Detection%20Lab-blue?style=for-the-badge&logo=splunk)
![SIEM](https://img.shields.io/badge/SIEM-Splunk%20Enterprise-orange?style=for-the-badge&logo=splunk)
![IDS](https://img.shields.io/badge/IDS-Suricata-red?style=for-the-badge)
![MITRE](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-darkred?style=for-the-badge)
![Blue Team](https://img.shields.io/badge/Team-Blue%20Team-blue?style=for-the-badge)

### Enterprise SOC Monitoring & Threat Detection Environment

Built using Splunk Enterprise, Sysmon, Suricata IDS, Apache, NGINX, and MITRE ATT&CK Mapping.

</div>

---

# 📌 Project Overview

This project is a hands-on enterprise-style SOC Monitoring & SIEM Threat Detection Lab designed to simulate real-world blue team operations, detection engineering workflows, and threat hunting activities.

The lab integrates multiple security technologies to monitor:

- Endpoint telemetry  
- Network attacks  
- Web attacks  
- Authentication abuse  
- PowerShell activity  
- Reverse shell behavior  
- Reconnaissance activity  

---

# 🏗️ Lab Architecture

| Machine | Role | Technology |
|---|---|---|
| Kali Linux | Attack Machine | Nmap, Hydra, SQLMap |
| Splunk Server | SIEM Platform | Splunk Enterprise |
| Windows Endpoint | Endpoint Monitoring | Sysmon |
| Web Server | Web Monitoring | Apache |
| Load Balancer | Traffic Distribution | NGINX |
| IDS Sensor | Network Detection | Suricata |

---

# 🚨 Splunk SPL Detection Rules

---

# 🔎 Nmap Port Scan Detection

## 🎯 Objective

Detect reconnaissance and port scanning activity.

---

## 🔍 SPL Query

```spl
index=suricata event_type=alert
| search alert.signature="ET SCAN*" OR alert.signature="*Nmap*"
| stats dc(dest_port) as unique_ports,
        count as total_events,
        values(alert.signature) as signatures
        by src_ip, dest_ip
| where unique_ports > 15
| sort - unique_ports
| eval alert="Nmap Port Scan Detected"
| table src_ip, dest_ip, unique_ports, total_events, signatures, alert
```

---

## ⚡ Attack Simulation

```bash
nmap -sS -sV -O -T4 10.0.1.139
```

---

## 🧠 Detection Logic

- Collects Suricata IDS alerts  
- Detects port scanning across multiple services  
- Identifies reconnaissance behavior  
- Aggregates attacker activity by source IP  
- Flags abnormal scanning patterns  

---

## 🎯 MITRE ATT&CK

| Tactic | Technique | ID |
|--------|-----------|----|
| Reconnaissance | Active Scanning | T1595 |

---

## 🚨 Severity

🟠 Medium

---

## 🛡️ SOC Response Actions

- Identify attacker source IP  
- Correlate with Sysmon + web logs  
- Check targeted ports/services  
- Block malicious IP  
- Monitor for follow-up exploitation  

---

# 💉 SQL Injection Detection

## 🔍 SPL Query

```spl
index=web sourcetype=access_combined
| rex field=uri "(?P<sqli>(UNION|SELECT|DROP|INSERT|OR 1=1|--))"
| where isnotnull(sqli)
| stats count by src_ip, uri, sqli
| sort -count
```

---

# 🔑 SSH Brute Force Detection

## 🔍 SPL Query

```spl
index=linux_secure sourcetype=linux_secure
| rex "Failed password for (?P<user>\S+) from (?P<src_ip>\S+)"
| stats count by src_ip, user
| where count > 5
| eval alert="SSH Brute Force Attack"
```

---

# ⚡ PowerShell Abuse Detection

## 🔍 SPL Query

```spl
index=sysmon EventCode=1
| search Image="*powershell.exe"
| search CommandLine="*EncodedCommand*" OR CommandLine="*IEX*"
| table _time, User, ComputerName, CommandLine
```

---

# 🌐 Reverse Shell Detection

## 🔍 SPL Query

```spl
index=sysmon EventCode=3
| search NOT DestinationPort=80 NOT DestinationPort=443
| stats count by ComputerName, DestinationIp, DestinationPort
| where count > 1
```

---

# 📊 Detection Engineering Skills Demonstrated

- Splunk SPL Query Development  
- SIEM Monitoring & Alerting  
- Threat Hunting  
- Endpoint Detection (Sysmon)  
- Network Security Monitoring (Suricata)  
- MITRE ATT&CK Mapping  
- Incident Investigation  
- Blue Team Operations  
- Log Correlation & Analysis  
- Detection Engineering  

---

# 🎯 Enterprise SOC Use Cases

- Web Attack Detection  
- Network Reconnaissance Detection  
- Authentication Monitoring  
- Endpoint Threat Detection  
- IDS Alert Correlation  
- Threat Hunting Operations  
- Incident Response Workflows  

---

# 🏢 Enterprise Relevance

This lab simulates real SOC environments with:

- Multi-source SIEM ingestion  
- Detection engineering workflows  
- Blue team monitoring  
- MITRE ATT&CK mapping  
- Incident response lifecycle  

---

# 🎓 Key Learning Outcomes

- Built enterprise SIEM monitoring pipeline  
- Created custom SPL detection rules  
- Integrated Sysmon + Suricata + Splunk  
- Simulated real-world cyber attacks  
- Performed threat hunting  
- Designed SOC-style detection workflows  

---

# 📬 Contact

| Platform | Link |
|---|---|
| Name | Parakh Shinde |
| LinkedIn | www.linkedin.com/in/parakh-shinde |
| Email | parakhshinde2002@gmail.com |


---

<div align="center">

### ⭐ SOC Monitoring | Detection Engineering | Blue Team Operations ⭐

</div>
