# sentinel.py

import datetime
import os
import socket
import requests
import subprocess
from urllib.parse import urlparse
import argparse
import ssl
from tqdm import tqdm
from colorama import Fore, Style, init

init(autoreset=True)
SECURITY_SCORE = 10  # Start with perfect score


def check_host_reachability(hostname: str) -> bool:
    try:
        subprocess.check_output(["ping", "-c", "1", "-W", "1", hostname], stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False


def scan_ports(host: str, ports_to_scan=100) -> str:
    open_ports = []
    common_ports = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080
    ]
    scanned_ports = common_ports[:ports_to_scan] if ports_to_scan < len(common_ports) else common_ports

    for port in scanned_ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            result = sock.connect_ex((host, port))
            if result == 0:
                try:
                    banner = sock.recv(1024).decode(errors='ignore').strip()
                except:
                    banner = ""
                open_ports.append(f"[+] Port {port} open {'- ' + banner if banner else ''}")

    return "\n".join(open_ports) if open_ports else "No common ports open."


def generate_report(target: str, protocol_preference: str = "https") -> str:
    global SECURITY_SCORE
    global target_name
    target_name=target
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    parsed_url = urlparse(target if target.startswith("http") else f"{protocol_preference}://{target}")
    hostname = parsed_url.hostname

    report_sections = []

    steps = [
        "Checking Host Reachability",
        "Resolving DNS",
        "Fetching DNS Records",
        "Checking SSL/TLS",
        "Checking HTTP Headers",
        "Analyzing Cookies",
        "Fetching robots.txt",
        "Fetching sitemap.xml",
        "Scanning Common Vulnerabilities",
        "Port Scanning"
    ]

    with tqdm(total=len(steps), desc="Scanning", ncols=100) as progress:

        if check_host_reachability(hostname):
            report_sections.append(f"📡 Host Reachable: {hostname} is up.")
        else:
            report_sections.append(f"🚫 Host Unreachable: {hostname} appears to be down.")
            SECURITY_SCORE -= 2
        progress.update(1)

        try:
            ip_address = socket.gethostbyname(hostname)
        except socket.gaierror:
            ip_address = "Resolution failed"
            SECURITY_SCORE -= 1
        report_sections.append(f"🧠 Resolved IP: {ip_address}")
        progress.update(1)

        record_types = ["A", "MX", "TXT", "SPF", "DMARC"]
        dns_records = []
        for record in record_types:
            try:
                result = subprocess.check_output(["nslookup", "-type=" + record, hostname], stderr=subprocess.DEVNULL, text=True)
                dns_records.append(f"{record} Records:\n{result.strip()}")
            except Exception:
                dns_records.append(f"{record} Records: Could not retrieve.")
                SECURITY_SCORE -= 0.2
        report_sections.append("🔍 DNS Records:\n- " + "\n- ".join(dns_records))
        progress.update(1)

        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    issuer = dict(x[0] for x in cert['issuer'])
                    ssl_info = f"SSL Certificate:\n  - Issuer: {issuer.get('organizationName', 'N/A')}\n  - Valid From: {cert['notBefore']}\n  - Valid To: {cert['notAfter']}"
        except Exception as e:
            ssl_info = f"SSL Certificate: Error - {str(e)}"
            SECURITY_SCORE -= 1
        report_sections.append(f"🔒 SSL/TLS Info:\n- {ssl_info}")
        progress.update(1)

        try:
            try:
                response = requests.get(f"{protocol_preference}://{hostname}", timeout=5)
            except:
                fallback = "https" if protocol_preference == "http" else "http"
                response = requests.get(f"{fallback}://{hostname}", timeout=5)

            headers = response.headers
            x_content_type = headers.get("X-Content-Type-Options", "Missing")
            x_frame_options = headers.get("X-Frame-Options", "Missing")
            x_xss_protection = headers.get("X-XSS-Protection", "Missing")
        except Exception:
            x_content_type = x_frame_options = x_xss_protection = "Connection failed"
            response = None
            SECURITY_SCORE -= 1

        if x_content_type == "Missing": SECURITY_SCORE -= 0.5
        if x_frame_options == "Missing": SECURITY_SCORE -= 0.5
        if x_xss_protection == "Missing": SECURITY_SCORE -= 0.5

        report_sections.append(f"🛡️ Security Headers:\n- X-Content-Type-Options: {x_content_type}\n- X-Frame-Options: {x_frame_options}\n- X-XSS-Protection: {x_xss_protection}")
        progress.update(1)

        cookies_info = "No cookies found"
        try:
            if response:
                cookies = response.cookies
                if cookies:
                    cookies_info = "\n".join([
                        f"  - {cookie.name}: HttpOnly={cookie._rest.get('HttpOnly', 'False')}, Secure={cookie.secure}, Domain={cookie.domain}" 
                        for cookie in cookies
                    ])
        except Exception:
            cookies_info = "Could not retrieve cookies."
        report_sections.append(f"🔐 Cookie Security:\n{cookies_info}")
        progress.update(1)

        try:
            rbt = requests.get(f"{protocol_preference}://{hostname}/robots.txt", timeout=5)
            if rbt.status_code == 200:
                robots_txt = rbt.text[:300] + ("..." if len(rbt.text) > 300 else "")
            else:
                robots_txt = "robots.txt not found"
        except Exception:
            robots_txt = "robots.txt retrieval failed"
        report_sections.append(f"📄 robots.txt:\n{robots_txt}")
        progress.update(1)

        try:
            sm = requests.get(f"{protocol_preference}://{hostname}/sitemap.xml", timeout=5)
            if sm.status_code == 200:
                sitemap_xml = (sm.text[:300] if len(sm.text) < 300 else "The sitemap.xml file is too large, please visit manually for the contents")
            else:
                sitemap_xml = "sitemap.xml not found"
        except Exception:
            sitemap_xml = "sitemap.xml retrieval failed"
        report_sections.append(f"📄 sitemap.xml:\n{sitemap_xml}")
        progress.update(1)

        paths_to_check = ["/admin", "/login", "/.env", "/config.php", "/backup.zip", "/api", "/js/app.js"]
        vuln_findings = []
        for path in paths_to_check:
            try:
                vuln_url = f"{protocol_preference}://{hostname}{path}"
                res = requests.get(vuln_url, timeout=5)
                if res.status_code == 200:
                    vuln_findings.append(f"{Fore.RED}[+] {path} found (Status: 200){Style.RESET_ALL}")
                    SECURITY_SCORE -= 0.5
                elif res.status_code == 403:
                    vuln_findings.append(f"{Fore.YELLOW}[!] {path} is forbidden (Status: 403){Style.RESET_ALL}")
                else:
                    vuln_findings.append(f"[-] {path} not found (Status: {res.status_code})")
            except Exception:
                vuln_findings.append(f"{Fore.BLUE}[-] {path} check failed.{Style.RESET_ALL}")
        vuln_scan_result = "\n".join(vuln_findings) if vuln_findings else "No common vulnerabilities detected."
        report_sections.append(f"🔓 Vulnerability Scanning:\n{vuln_scan_result}")
        progress.update(1)

        try:
            port_scan_result = scan_ports(hostname)
            if "Port 21" in port_scan_result or "Port 23" in port_scan_result or "Port 3306" in port_scan_result:
                SECURITY_SCORE -= 1
        except Exception as e:
            port_scan_result = f"Error during port scanning: {e}"
            SECURITY_SCORE -= 1
        report_sections.append(f"🔌 Port Scan Result:\n{port_scan_result}")
        progress.update(1)

    SECURITY_SCORE = max(0, round(SECURITY_SCORE, 2))
    score_emoji = "🟢" if SECURITY_SCORE >= 8 else "🟡" if SECURITY_SCORE >= 5 else "🔴"
    report_sections.append(f"\n📊 Overall Security Score: {SECURITY_SCORE}/10 {score_emoji}")

    return f"""
Sentinel Security Assessment Report
-----------------------------------
🕒 Timestamp: {timestamp}
📌 Target: {target}

""" + "\n\n".join(report_sections) + "\n\nSuggestions: Review DNS records, secure SSL certs, enforce HTTP headers, validate domain ownership, minimize exposure via sitemap and robots.txt.\n" + "\nRecommendation: Consider manual pentesting for an in-depth security testing and analysis"


# Remaining code (save_report, main, etc.) stays unchanged...

def save_report(report_data: str, filename: str, title: str = "Security Assessment Report", target: str = "Unknown Target", score: float = 0.0):
    full_path = os.path.abspath(filename)
    file_ext = os.path.splitext(filename)[1].lower()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if file_ext == ".html":
        # HTML formatting block
        report_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{title}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            background-color: #f9f9f9;
            margin: 20px;
            color: #333;
        }}
        h1, h2 {{
            color: #222;
        }}
        .section {{
            background: white;
            border-left: 5px solid #444;
            padding: 15px;
            margin: 20px 0;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-radius: 8px;
        }}
        .score {{
            font-size: 1.8em;
            color: #2980b9;
            text-align: center;
            margin-top: 20px;
        }}
        pre {{
            background-color: #f4f4f4;
            padding: 10px;
            overflow-x: auto;
            white-space: pre-wrap;
            border-radius: 6px;
            border: 1px solid #ddd;
        }}
        footer {{
            margin-top: 40px;
            font-size: 0.9em;
            text-align: center;
            color: #999;
        }}
    </style>
</head>
<body>
    <h1>🔐 {title}</h1>
    <p><strong>Target:</strong> {target_name}</p>
    <p><strong>Generated on:</strong> {timestamp}</p>

    <div class="score">
        Overall Security Score: <strong>{SECURITY_SCORE}/10</strong>
    </div>

    <div class="section">
        <h2>Scan Findings</h2>
        <pre>{report_data}</pre>
    </div>

    <footer>
        <p>This report was generated by SecureT Sentinel Scanner.</p>
        <p><em>Note: This is a prototype. False positives may exist. For deeper insights, contact <strong>SecureT</strong>.</em></p>
    </footer>
</body>
</html>
"""
    else:
        # Plain text fallback
        report_content = report_data

    with open(full_path, "w", encoding="utf-8") as f:
        f.write(report_content)

    print(f"💾 Report saved as {full_path}")


def main():
    parser = argparse.ArgumentParser(
        description="""
Sentinel: Security Assessment CLI Tool

Performs basic recon on a target domain.
        """,
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=True
    )
    parser.add_argument("--target", "-t", required=True, help="Target domain or IP")
    parser.add_argument(
        "--output", "-o",
        help="Filename to save the report (e.g., report.txt or report.html)"
    )
    parser.add_argument(
        "--silent", action="store_true",
        help="Run silently: suppress terminal output and save results to file only (requires -o)"
    )
    parser.add_argument(
        "--protocol", choices=["http", "https"], default="https",
        help="Preferred protocol to use (default: https)"
    )

    args = parser.parse_args()

    try:
        report_data = generate_report(args.target, args.protocol)
    except Exception as e:
        print(f"❌ An unexpected error occurred: {str(e)}")
        return

    if args.silent:
        if not args.output:
            parser.error("--silent requires --output to be specified.")
        save_report(report_data, args.output)
    elif args.output:
        save_report(report_data, args.output)
        print("\n--- Report Output ---\n")
        print(report_data)
    else:
        print(report_data)


if __name__ == "__main__":
    main()
