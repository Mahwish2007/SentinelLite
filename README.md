# SentinelLite – Network Recon & Log Correlation Alert Engine

SentinelLite is a Python-based cybersecurity monitoring and analysis tool developed as an academic security project. It combines network reconnaissance, traffic inspection, and log correlation techniques to simulate real-world SOC (Security Operations Center) detection workflows.

---

## 🚀 Project Objectives

The goal of SentinelLite is to demonstrate how multiple security data sources can be analyzed together to detect potentially malicious activity across a network environment.

The tool integrates:

- **Nmap network host discovery**
- **PCAP traffic analysis (4 detection tests)**
- **Web server access log parsing**
- **Static blocklist validation**
- **IP activity correlation**
- **Risk severity classification**
- **Automated CSV & HTML report generation**
- **Optional alert email notifications**

This project showcases skills relevant to:

- Network security monitoring  
- Threat detection principles  
- Python automation and scripting  
- Incident reporting workflows  
- Data correlation and analysis techniques

---

## ⚙️ Key Features

### 🔍 Network Scanning
Discovers active hosts using:
nmap -sn

### 📦 PCAP Analysis (4 Detection Tests)
- **Traffic Volume Test**
- **Source IP Distribution Test**
- **Protocol & Port Analysis Test**
- **Packet Size Similarity Test**

These tests help identify:
- Potential DDoS traffic
- SYN flood patterns
- DNS abuse
- Packet replay behavior

---

### 📄 Log Analysis
Parses Apache / Nginx **access logs** to:
- Count HTTP requests per IP address
- Identify abnormal request activity
- Export findings to CSV

---

### 🔗 Correlation Engine

Combines results from:

- Nmap live-host discovery  
- PCAP packet analysis  
- Web server request counts  
- Known static blocklists  

Each IP is assigned a **severity level**:
- **LOW**
- **MEDIUM**
- **HIGH**
- **CRITICAL**

---

### 📊 Reporting

Generates:

- CSV datasets  
- HTML security report including:
  - Test summaries
  - Detected threats
  - Severity classification tables

---

### ✉️ Email Alerts (Optional)

When threats are detected, the system can send automatic notifications containing:

- Summary descriptions
- Attached HTML incident reports

Email credentials are secured via **environment variables** rather than hard-coded values.

---

---

## 🛠️ Technologies Used

- **Python 3**
- **Nmap**
- **dpkt**
- **Pandas**
- **SMTP Email Client**
- **Regex & JSON processing**

---

---

## 📈 Learning Outcomes

This project demonstrates applied understanding of:

- Network reconnaissance tools
- Packet capture analysis
- Log forensics
- SIEM-style correlation logic
- Threat severity classification
- Secure coding practices

---

---

## ▶️ Usage

1. Install dependencies: pip install -r requirements.txt
2. Set email environment variables (optional):
SENTINELLITE_SENDER_EMAIL
SENTINELLITE_APP_PASSWORD
SENTINELLITE_RECIPIENT_EMAIL
3. Run:python sentinel_lite.py
   
Reports will be generated automatically.
