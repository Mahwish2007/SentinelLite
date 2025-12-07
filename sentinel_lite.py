#!/usr/bin/env python3
"""
SentinelLite — Real-time Network Recon & Log-Correlation Alert Engine

This script performs:
- Nmap host discovery
- PCAP analysis with 4 detection tests
- HTTP access.log analysis
- Correlation of results to identify suspicious IPs
- Report generation (CSV + HTML)
- Optional email alert with IRP attachment

GitHub-safe version:
- No hard-coded passwords
- Uses environment variables for email settings
"""

import os
import re
import json
import time
import socket
import subprocess
from collections import Counter
from datetime import datetime

import dpkt
import pandas as pd
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders


# ================================
# CONFIGURATION
# ================================

# Subnet
NMAP_SUBNET = "192.168.1.0/24"

PCAP_PATH = "traffic.pcap"
ACCESS_LOG_PATH = "logs/access.log"
SCAN_JSON_PATH = "scans/last_scan.json"
LOG_STATS_CSV = "data/log_ip_stats.csv"
SUSPICIOUS_CSV = "data/suspicious_ips.csv"
HTML_REPORT_PATH = "report/alert_report.html"

# BLOCKLIST (known malicious IPs)
BLOCKLIST = [
    "185.220.101.1",    # Tor exit
    "45.153.160.112",   # VPN/proxy
    "92.118.36.72",     # Bruteforce scanner
    "104.244.72.116",   # Botnet relay
]

# Email alert settings (READ FROM ENV VARIABLES)
# Set these in your environment, NOT in code:
#   SENTINELLITE_SENDER_EMAIL
#   SENTINELLITE_APP_PASSWORD
#   SENTINELLITE_RECIPIENT_EMAIL (optional – defaults to sender)
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

SENDER_EMAIL = os.environ.get("SENTINELLITE_SENDER_EMAIL", "")
SENDER_APP_PASSWORD = os.environ.get("SENTINELLITE_APP_PASSWORD", "")
RECIPIENT_EMAIL = os.environ.get(
    "SENTINELLITE_RECIPIENT_EMAIL",
    SENDER_EMAIL  # default to sender if not provided
)

# Attachment (optional – your IRP PDF if you have one)
IRP_PDF_PATH = "IRP_SentinelLite.pdf"


# ================================
# HELPER FUNCTIONS
# ================================

def ensure_directories():
    """Create necessary folders."""
    for path in ["scans", "logs", "data", "report"]:
        os.makedirs(path, exist_ok=True)


# ================================
# NMAP SCAN
# ================================

def run_nmap_scan(subnet: str = NMAP_SUBNET, output_path: str = SCAN_JSON_PATH):
    """Run Nmap host discovery and parse results."""
    print(f"\n[+] Running Nmap host discovery on {subnet} ...")

    cmd = ["nmap", "-sn", subnet, "-oG", "-"]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except Exception as e:
        print(f"[!] Nmap failed: {e}")
        return []

    hosts = []

    for line in result.stdout.splitlines():
        if line.startswith("Host:"):
            ip_match = re.search(r"Host:\s+(\S+)", line)
            if not ip_match:
                continue
            ip = ip_match.group(1)
            state = "up" if "Up" in line else "down"
            hosts.append({"host": ip, "state": state})

    with open(output_path, "w") as f:
        json.dump(hosts, f, indent=2)

    print(f"[+] Nmap scan found {len(hosts)} hosts. Saved to {output_path}")
    return hosts


# ================================
# PCAP ANALYSIS (4 TESTS)
# ================================

def analyze_pcap(file_path: str):
    """Analyze PCAP file using 4 detection tests."""
    print(f"\n[+] Analyzing PCAP file: {file_path}")

    if not os.path.exists(file_path):
        print(f"[!] ERROR: PCAP file not found: {file_path}")
        return {
            "traffic_volume_attack": False,
            "ip_address_attack": False,
            "protocol_attack": False,
            "packet_size_attack": False,
            "per_ip_packet_counts": Counter(),
            "execution_time": 0,
        }

    start_time = time.time()

    with open(file_path, "rb") as f:
        pcap = dpkt.pcap.Reader(f)
        packets = list(pcap)

    if not packets:
        print("[!] PCAP contains no packets.")
        return {
            "traffic_volume_attack": False,
            "ip_address_attack": False,
            "protocol_attack": False,
            "packet_size_attack": False,
            "per_ip_packet_counts": Counter(),
            "execution_time": 0,
        }

    # TEST 1: TRAFFIC VOLUME
    packet_count = len(packets)
    duration = packets[-1][0] - packets[0][0] or 1
    packet_rate = packet_count / duration
    traffic_volume_attack = packet_rate > 1000  # simple threshold

    print(f"\n--- Test 1: Traffic Volume ---")
    print(f"Total packets: {packet_count}")
    print(f"Duration: {duration:.2f}s")
    print(f"Rate: {packet_rate:.2f} pkts/sec")

    # TEST 2: IP DISTRIBUTION
    print("\n--- Test 2: IP Address Distribution ---")
    src_ips = []

    for ts, buf in packets:
        eth = dpkt.ethernet.Ethernet(buf)
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data
            src_ip = socket.inet_ntoa(ip.src)
            src_ips.append(src_ip)

            # Check against static blocklist
            if src_ip in BLOCKLIST:
                print(f"[!] BLOCKLIST MATCH DETECTED in PCAP: {src_ip}")

    src_counter = Counter(src_ips)
    unique_ips = len(src_counter)
    ip_address_attack = unique_ips > 100  # threshold for "many sources"

    print(f"Unique IPs: {unique_ips}")
    print("Top 5 source IPs:")
    for ip_addr, count in src_counter.most_common(5):
        print(f"  {ip_addr}: {count} packets")

    # TEST 3: PROTOCOL & PORT ANALYSIS
    print("\n--- Test 3: Protocol & Port Analysis ---")
    tcp_syn = udp = dns = 0

    for ts, buf in packets:
        eth = dpkt.ethernet.Ethernet(buf)
        if not isinstance(eth.data, dpkt.ip.IP):
            continue
        ip = eth.data

        if isinstance(ip.data, dpkt.tcp.TCP):
            tcp = ip.data
            if tcp.flags & dpkt.tcp.TH_SYN:
                tcp_syn += 1

        elif isinstance(ip.data, dpkt.udp.UDP):
            udp += 1
            udp_pkt = ip.data
            if udp_pkt.dport == 53 or udp_pkt.sport == 53:
                dns += 1

    print(f"SYN packets: {tcp_syn}")
    print(f"UDP packets: {udp}")
    print(f"DNS packets: {dns}")

    protocol_attack = tcp_syn > 100 or udp > 500 or dns > 200

    # TEST 4: PACKET SIZE
    print("\n--- Test 4: Packet Size ---")
    packet_sizes = []

    for ts, buf in packets:
        eth = dpkt.ethernet.Ethernet(buf)
        if isinstance(eth.data, dpkt.ip.IP):
            packet_sizes.append(len(eth.data))

    size_distribution = Counter(packet_sizes)
    packet_size_attack = len(size_distribution) == 1  # all same size suspicious

    print("Top packet sizes:")
    for size, cnt in size_distribution.most_common(5):
        print(f"  {size} bytes: {cnt} packets")

    execution_time = time.time() - start_time

    return {
        "traffic_volume_attack": traffic_volume_attack,
        "ip_address_attack": ip_address_attack,
        "protocol_attack": protocol_attack,
        "packet_size_attack": packet_size_attack,
        "per_ip_packet_counts": src_counter,
        "execution_time": execution_time,
    }


# ================================
# LOG ANALYSIS
# ================================

def analyze_access_log(log_path: str = ACCESS_LOG_PATH):
    """Analyze Apache/Nginx access.log file."""
    print(f"\n[+] Analyzing access log: {log_path}")

    if not os.path.exists(log_path):
        print("[!] No access.log found, skipping log analysis.")
        return pd.DataFrame(columns=["ip", "http_requests"])

    ip_counter = Counter()
    pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+)")

    with open(log_path, "r", errors="ignore") as f:
        for line in f:
            match = pattern.search(line)
            if match:
                ip_counter[match.group(1)] += 1

    df = pd.DataFrame(
        [{"ip": ip, "http_requests": count} for ip, count in ip_counter.items()]
    )

    df.to_csv(LOG_STATS_CSV, index=False)
    print(f"[+] Saved log stats → {LOG_STATS_CSV}")

    return df


# ================================
# SUSPICIOUS IP CORRELATION
# ================================

def correlate_results(nmap_hosts, pcap_stats, log_df):
    """Combine Nmap + PCAP + Logs and generate suspicious IP report."""
    print("\n[+] Correlating results...")

    packets = pcap_stats["per_ip_packet_counts"]
    http_requests = {row["ip"]: row["http_requests"] for _, row in log_df.iterrows()}
    nmap_up = {h["host"] for h in nmap_hosts if h["state"] == "up"}

    combined_ips = set(packets) | set(http_requests) | nmap_up
    results = []

    for ip in combined_ips:
        pkt = packets.get(ip, 0)
        req = http_requests.get(ip, 0)
        in_nmap = ip in nmap_up

        # Static blocklist flag
        static_blocklisted = ip in BLOCKLIST

        # Severity logic
        if static_blocklisted:
            severity = "CRITICAL"
        elif pkt > 5000 or (pkt > 1000 and req > 100) or in_nmap:
            severity = "HIGH"
        elif pkt > 1000 or req > 100:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        results.append({
            "ip": ip,
            "packets": pkt,
            "http_requests": req,
            "in_nmap_scan": in_nmap,
            "blocklisted_static": static_blocklisted,
            "severity": severity,
        })

    df = pd.DataFrame(results)
    df.to_csv(SUSPICIOUS_CSV, index=False)

    print(f"[+] Saved suspicious IPs → {SUSPICIOUS_CSV}")
    return df


# ================================
# HTML REPORT
# ================================

def generate_html_report(suspicious_df, pcap_stats):
    """Generate HTML report."""
    print(f"\n[+] Generating HTML report → {HTML_REPORT_PATH}")

    attack_detected = any([
        pcap_stats["traffic_volume_attack"],
        pcap_stats["ip_address_attack"],
        pcap_stats["protocol_attack"],
        pcap_stats["packet_size_attack"],
    ])

    status = "Potential Attack Detected" if attack_detected else "No Attack Detected"

    html = f"""
    <html><body>
    <h1>SentinelLite Alert Report</h1>
    <p>Generated: {datetime.now().isoformat(sep=' ', timespec='seconds')}</p>
    <p>Status: <b>{status}</b></p>
    <h2>PCAP Test Summary</h2>
    <ul>
        <li>Traffic volume attack: {pcap_stats["traffic_volume_attack"]}</li>
        <li>IP distribution attack: {pcap_stats["ip_address_attack"]}</li>
        <li>Protocol attack: {pcap_stats["protocol_attack"]}</li>
        <li>Packet size attack: {pcap_stats["packet_size_attack"]}</li>
        <li>PCAP analysis time: {pcap_stats["execution_time"]:.2f} seconds</li>
    </ul>
    <h2>Suspicious IPs (including static blocklist flag)</h2>
    {suspicious_df.to_html(index=False)}
    </body></html>
    """

    with open(HTML_REPORT_PATH, "w") as f:
        f.write(html)

    print("[+] HTML report generated.")


# ================================
# EMAIL ALERT
# ================================

def send_email_alert(subject: str, body: str, attachment_path: str = HTML_REPORT_PATH):
    """Send an email alert with optional attachment."""

    if not SENDER_EMAIL or not SENDER_APP_PASSWORD:
        print("[!] Email not sent: email environment variables not configured.")
        return

    print(f"\n[+] Sending email alert to {RECIPIENT_EMAIL} ...")

    msg = MIMEMultipart()
    msg["From"] = SENDER_EMAIL
    msg["To"] = RECIPIENT_EMAIL
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    if attachment_path and os.path.exists(attachment_path):
        with open(attachment_path, "rb") as f:
            part = MIMEBase("application", "octet-stream")
            part.set_payload(f.read())
        encoders.encode_base64(part)
        part.add_header(
            "Content-Disposition",
            f"attachment; filename={os.path.basename(attachment_path)}",
        )
        msg.attach(part)

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_APP_PASSWORD)
            server.send_message(msg)
        print("[+] Email alert sent successfully.")
    except Exception as e:
        print(f"[!] Failed to send email: {e}")


# ================================
# MAIN FUNCTION
# ================================

def main():
    ensure_directories()

    nmap_hosts = run_nmap_scan()
    pcap_stats = analyze_pcap(PCAP_PATH)
    log_df = analyze_access_log()
    suspicious_df = correlate_results(nmap_hosts, pcap_stats, log_df)
    generate_html_report(suspicious_df, pcap_stats)

    # Decide if we should send an email
    attack_detected = any([
        pcap_stats["traffic_volume_attack"],
        pcap_stats["ip_address_attack"],
        pcap_stats["protocol_attack"],
        pcap_stats["packet_size_attack"],
    ])

    if attack_detected or not suspicious_df.empty:
        subject = "SentinelLite Alert - Potential Suspicious Activity"
        body = (
            "SentinelLite has detected potential suspicious or attack-like activity.\n"
            "Please review the attached report (HTML) and the IRP (if provided)."
        )
        send_email_alert(subject, body, HTML_REPORT_PATH)

    print("\n[✓] SentinelLite complete.\n")


if __name__ == "__main__":
    main()

