# Security Assessment CLI Tool

A comprehensive command-line based security assessment prototype designed for preliminary reconnaissance and vulnerability checks on websites. This tool helps demonstrate potential security issues to clients and includes multiple automated checks across different categories.

---

## Features

- **Basic Reconnaissance**

  - Subdomain enumeration
  - WHOIS lookup
  - DNS analysis

- **Website Security Analysis**

  - SSL/TLS check
  - HTTP headers inspection
  - Cookie security checks
  - Outdated software detection

- **Vulnerability Scanning**

  - Admin panel discovery
  - Directory enumeration
  - Sensitive file detection
  - API exposure
  - JavaScript leaks

- **Open Port & Service Enumeration**

  - Port scanning
  - Service detection
  - Exposed databases identification

- **Email & SPF Security Checks**

  - SPF, DKIM, and DMARC analysis
  - Mail server misconfiguration detection

- **Data Breach & Reputation Analysis**

  - Pwned email checks
  - Blacklist monitoring

- **Custom Report Generation**

  - PDF/HTML output
  - Risk ratings
  - Embedded screenshots

- **Bonus Enhancements**

  - Automated Proof-of-Concept (PoC) generation
  - OSINT API integrations
  - CI/CD integration for continuous assessments
  - Attack surface mapping

---

## Usage

```bash
python3 main.py --url https://example.com
```

The tool will run all scans sequentially with a progress bar. After execution, it provides:

- Detailed scan report
- Overall security score out of 10
- Clear indication that the tool is a prototype and may yield false positives
- Suggestion to reach out to the LinuxMantra team for a deeper analysis

---

## Requirements

Install dependencies:

```bash
pip install -r requirements.txt
```

### `requirements.txt`

```
requests
tqdm
colorama
```

---

## Disclaimer

This tool is for **educational and demonstration purposes only**. It is a **prototype** and may contain **false positives**. Use only on systems you own or have explicit permission to assess.

For a detailed and professional assessment, contact the **LinuxMantra** team.

---

## License

Sentinel Scanner by Abhishek Kumar Singh Copyright (C) 2025.



This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.



This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.



You should have received a copy of the GNU General Public License along with this program. If not, see [http://www.gnu.org/licenses/](http://www.gnu.org/licenses/)

