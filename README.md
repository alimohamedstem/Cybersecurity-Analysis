# 🛡️ Linux Server Breach & Hardening Analysis

This repository documents a **simulated security breach analysis** and remediation process on a Linux server. It walks through every phase of the **incident response lifecycle**—from detection and attacker analysis to containment, eradication, and system hardening.

---

## 📚 Table of Contents

- [📌 Executive Summary](#-executive-summary)
- [🔍 Detailed Analysis & Findings](#-detailed-analysis--findings)
  - [1. Initial Compromise: SSH Brute Force](#1-initial-compromise-ssh-brute-force)
  - [2. Malware Deployment & C2 Communication](#2-malware-deployment--c2-communication)
  - [3. Persistence Mechanisms](#3-persistence-mechanisms)
  - [4. Vulnerability Assessment](#4-vulnerability-assessment)
- [🔧 Remediation & System Hardening](#-remediation--system-hardening)
  - [1. Containment: Blocking Attacker IP](#1-containment-blocking-attacker-ip)
  - [2. Eradication: Removing Malicious Artifacts](#2-eradication-removing-malicious-artifacts)
  - [3. Hardening: SSH Service](#3-hardening-ssh-service)
  - [4. Hardening: Apache Web Server](#4-hardening-apache-web-server)
- [✅ Conclusion & Recommendations](#-conclusion--recommendations)

---

## 📌 Executive Summary

An attacker from IP `192.168.56.1` successfully breached the server via an **SSH brute-force attack**. The attacker:

- Installed **malware agents** and a **cryptominer**
- Created a **rogue user account**
- Established a **backdoor listener**
- Communicated with a **hardcoded C2 domain**

Logs and antivirus scans confirmed the intrusion. The report details how the breach was contained, artifacts removed, and the system hardened.

---

## 🔍 Detailed Analysis & Findings

### 1. Initial Compromise: SSH Brute Force

- **Vector**: SSH brute-force  
- **Attacker IP**: `192.168.56.1`  
- **Log Evidence**:
  - `/var/log/auth.log`
  - `/var/ossec/logs/alerts.log`

Successful login attempts originated from `192.168.1.14`, indicating internal lateral movement.

---

### 2. Malware Deployment & C2 Communication

**Malicious Files Identified by ClamAV:**

| Filename                          | Detection Name                     |
|----------------------------------|------------------------------------|
| `/home/ubuntu/Downloads/ft32`    | Unix.Malware.Agent-6774375-0       |
| `/home/ubuntu/Downloads/ft64`    | Unix.Malware.Agent-6774336-0       |
| `/home/ubuntu/Downloads/wipefs`  | Unix.Tool.Miner-6443173-0          |

**C2 Infrastructure:**

- **Files**: `SSH-T`, `SSH-One`  
- **C2 Domain**: `http://darkl0rd.com:7758`

---

### 3. Persistence Mechanisms

- **Rogue User**: `darklord`  
- **Backdoor Listener**: `/tmp/remotesec -k -l 56565`  
- **Port Used**: `56565`

---

### 4. Vulnerability Assessment

- **Tool Used**: Greenbone Security Assistant (GSA)  
- **Findings**:
  - 18 low-severity
  - 2 medium-severity
  - **CVSS Score**: 4.3 (Medium)
  - **Outdated Apache Version**: `Apache/2.4.7 (Ubuntu)`

---

## 🔧 Remediation & System Hardening

### 1. Containment: Blocking Attacker IP

```bash
sudo ufw deny from 192.168.56.1 to any port 22
```

---

### 2. Eradication: Removing Malicious Artifacts

```bash
# Kill backdoor process
killall remotesec

# Remove malware files
rm /home/ubuntu/Downloads/ft32
rm /home/ubuntu/Downloads/ft64
rm /home/ubuntu/Downloads/wipefs

# Remove C2-related files
rm ~/SSH-T ~/SSH-One

# Delete rogue user
sudo deluser darklord
```

---

### 3. Hardening: SSH Service

**Recommendations:**

- 🔐 Enforce **key-based authentication** only  
- 🚫 Disable password authentication:
  ```ini
  PasswordAuthentication no
  ```
- 🛡️ Install Fail2Ban:
  ```bash
  sudo apt install fail2ban
  ```

---

### 4. Hardening: Apache Web Server

**Configuration Updates:**

- ✅ **Run under a non-privileged user**
  ```apache
  # /etc/apache2/apache2.conf
  User apache-user
  Group apache-group
  ```

- 🔒 **Hide server version and signature**
  ```apache
  # /etc/apache2/conf-enabled/security.conf
  ServerTokens Prod
  ServerSignature Off
  ```

- 📦 **Upgrade Apache version**
  ```bash
  sudo apt update
  sudo apt install apache2
  ```

---

## ✅ Conclusion & Recommendations

The server experienced a **multi-stage intrusion** due to insufficient SSH protection and outdated services. The response followed industry best practices to:

- Contain the breach  
- Remove all traces of the attacker  
- Harden the system for future resilience

**Ongoing Recommendations:**

- 🕵️ Continuous monitoring with OSSEC and log analyzers  
- 🔁 Regular vulnerability scans and authenticated patching  
- 📅 Timely updates to all services  
- 🔐 Enforce the **principle of least privilege** for user and service accounts

---

> 📝 _This report is part of a cybersecurity simulation project to practice digital forensics and incident response. All attack artifacts were generated in a controlled lab environment._
