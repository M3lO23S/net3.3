🎩 Net Hat 3.3 - Advanced Vulnerability Scanner
<p align="center"> <img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=700&size=30&pause=1000&color=FF0000&center=true&vCenter=true&width=600&lines=Net+Hat+3.3;Advanced+Vulnerability+Scanner;By+moshta3el+%40JYI_L" alt="Net Hat 3.3" /> </p><p align="center"> <img src="https://img.shields.io/badge/Version-3.3-red?style=for-the-badge&logo=github" alt="Version 3.3" /> <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python" alt="Python 3.8+" /> <img src="https://img.shields.io/badge/License-Ethical%20Use%20Only-orange?style=for-the-badge" alt="Ethical Use Only" /> <img src="https://img.shields.io/badge/Developer-moshta3el-red?style=for-the-badge&logo=telegram" alt="Developer: moshta3el" /> <img src="https://img.shields.io/badge/Telegram-%40JYI_L-blue?style=for-the-badge&logo=telegram" alt="Telegram: @JYI_L" /> </p>
📖 About Net Hat 3.3
Net Hat 3.3 is a professional, advanced vulnerability scanner designed for ethical hackers, penetration testers, and cybersecurity professionals. It performs deep, comprehensive scanning of web applications to detect every possible vulnerability from critical to informational.

⚠️ IMPORTANT: This tool is for educational and ethical purposes only. Use it ONLY on websites you own or have written permission to test. Unauthorized testing is illegal and punishable by law.

🔥 Features
🎯 Comprehensive Vulnerability Detection
Severity	Types Detected
🔴 CRITICAL	SQL Injection, RCE, LFI, RFI, Path Traversal, Sensitive File Exposure
🟡 HIGH	XSS (Reflected/Stored/DOM), CSRF, No HTTPS, Weak SSL/TLS
🟠 MEDIUM	Directory Listing, Missing Security Headers, Hidden Form Fields, Insecure Cookies
🟢 LOW	Email Disclosure, Phone Disclosure, Info in Comments, Image Alt Info
⚪ INFO	Open Ports, Server Information, Technology Detection, API Endpoints
🚀 Advanced Capabilities
Deep Crawling - Crawls up to depth 5 with full link discovery

Form Analysis - Analyzes every form for vulnerabilities (CSRF, hidden fields, GET/POST)

JavaScript Analysis - Extracts API endpoints, sensitive keywords, and variables

Source Code Harvesting - Attempts to retrieve .php, .js, .css, .html source files

Parameter Extraction - Extracts all URL and HTML parameters

Cookie Security Analysis - Checks for Secure, HttpOnly, SameSite flags

Security Headers Check - Checks for X-Frame-Options, CSP, HSTS, and more

SSL/TLS Validation - Checks certificate expiry and issuer

Technology Fingerprinting - Detects frameworks, CMS, servers, databases

Port Scanning - Scans 40+ common ports for open services

Directory Listing Detection - Finds exposed directories

Sensitive File Discovery - Finds .env, .git, config.php, etc.

📊 What the Report Contains
The JSON report includes everything discovered during the scan:

json
{
  "tool": "Net Hat 3.3",
  "developer": "moshta3el",
  "telegram": "@JYI_L",
  "target": "https://example.com",
  "scan_time": "2026-07-03T14:30:22.123456",
  "duration_seconds": 45.67,
  "vulnerabilities": [...],
  "open_ports": [...],
  "server_info": {...},
  "sensitive_files": [...],
  "links": [...],
  "forms": [...],
  "scripts": [...],
  "images": [...],
  "files": [...],
  "api_endpoints": [...],
  "hidden_comments": [...],
  "emails": [...],
  "phones": [...],
  "technologies": [...],
  "security_headers": {...},
  "cookies": [...],
  "source_files": [...],
  "directories": [...],
  "parameters": [...],
  "js_variables": [...],
  "ssl_info": {...},
  "summary": {
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "info": 0
  },
  "statistics": {
    "total_links": 0,
    "total_forms": 0,
    "total_scripts": 0,
    "total_images": 0,
    "total_files": 0,
    "total_api_endpoints": 0,
    "total_emails": 0,
    "total_phones": 0,
    "total_source_files": 0,
    "total_directories": 0,
    "total_parameters": 0,
    "total_js_variables": 0
  }
}
🚀 Installation
Prerequisites
Python 3.8 or higher

pip (Python package manager)

Step 1: Clone or Download
bash
# Clone the repository
git clone https://github.com/moshta3el/Net-Hat-3.3.git
cd Net-Hat-3.3
Step 2: Install Dependencies
bash
pip install -r requirements.txt
requirements.txt
txt
requests==2.31.0
beautifulsoup4==4.12.2
urllib3==2.0.4
Step 3: Run the Tool
bash
python Net_Hat_3.3.py -u https://target.com
📖 Usage Guide
Basic Scan
bash
python Net_Hat_3.3.py -u https://juice-shop.herokuapp.com
Advanced Scan with Custom Settings
bash
# Deep scan with max depth and threads
python Net_Hat_3.3.py -u https://target.com -d 5 -t 30

# Save report with custom name
python Net_Hat_3.3.py -u https://target.com -o my_scan_report.json

# Skip specific tests for faster scanning
python Net_Hat_3.3.py -u https://target.com --no-ports --no-sql
Command Line Options
Option	Description	Default
-u, --url	Target URL (required)	-
-d, --depth	Crawl depth	5
-t, --threads	Number of threads	20
-o, --output	Custom report filename	auto-generated
--no-ports	Skip port scanning	False
--no-sql	Skip SQL injection testing	False
--no-xss	Skip XSS testing	False
-v, --verbose	Verbose output	False
🎯 Testing Examples
Test on OWASP Juice Shop (Free & Legal)
bash
python Net_Hat_3.3.py -u https://juice-shop.herokuapp.com
Test on Local DVWA
bash
python Net_Hat_3.3.py -u http://localhost/dvwa -d 3 -t 10
Test with Custom Report Name
bash
python Net_Hat_3.3.py -u https://juice-shop.herokuapp.com -o juice_shop_full_scan.json
📁 Output Structure
After scanning, the tool creates:

text
Net-Hat-3.3/
├── Net_Hat_3.3.py          # Main tool
├── requirements.txt         # Dependencies
├── README.md               # This file
└── reports/                # Auto-created reports folder
    ├── target_domain_20260703_143022.json
    ├── target_domain_20260703_151045.json
    └── ...
Report Naming Convention
text
{domain}_{timestamp}.json
Example: juice-shop_herokuapp_com_20260703_143022.json

🛡️ Legal Disclaimer
⚠️ WARNING: This tool is for EDUCATIONAL and ETHICAL purposes only.

Do NOT use this tool on any website without explicit written permission.

Unauthorized testing is ILLEGAL and punishable by law.

The developer (moshta3el) is NOT responsible for any misuse.

Always obtain proper authorization before testing.

Laws by Region
Region	Law
USA	CFAA (Computer Fraud and Abuse Act)
EU	GDPR & NIS Directive
Egypt	Cybercrime Law No. 175/2018
UAE	Cybercrime Law No. 5/2012
Saudi Arabia	Anti-Cyber Crime Law
🔧 Troubleshooting
Common Issues
Issue	Solution
ModuleNotFoundError	Run pip install -r requirements.txt
Connection timeout	Increase timeout or check target accessibility
SSL errors	Tool disables SSL verification for testing
Permission denied	Run with appropriate user permissions
No results found	Target may be protected or not vulnerable
Verbose Mode
bash
python Net_Hat_3.3.py -u https://target.com -v
🎨 Screenshots
Startup Banner
text
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║     ███╗   ██╗███████╗████████╗     ██╗  ██╗ █████╗ ████████╗                ║
║     ████╗  ██║██╔════╝╚══██╔══╝     ██║  ██║██╔══██╗╚══██╔══╝                ║
║     ██╔██╗ ██║█████╗     ██║        ███████║███████║   ██║                   ║
║     ██║╚██╗██║██╔══╝     ██║        ██╔══██║██╔══██║   ██║                   ║
║     ██║ ╚████║███████╗   ██║        ██║  ██║██║  ██║   ██║                   ║
║     ╚═╝  ╚═══╝╚══════╝   ╚═╝        ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝                   ║
║                                                                              ║
║    ╔══════════════════════════════════════════════════════════════════════╗   ║
║    ║  Version: 3.3                    Developer: moshta3el               ║   ║
║    ║  Telegram: @JYI_L                For Ethical Hacking Only          ║   ║
║    ╚══════════════════════════════════════════════════════════════════════╝   ║
╚══════════════════════════════════════════════════════════════════════════════╝
Scan Progress
text
[*] Target: https://juice-shop.herokuapp.com
[*] Max Depth: 5
[*] Threads: 20
[*] Timeout: 10s
[*] Started: 2026-07-03 14:30:22
================================================================================

[+] PHASE 1: Advanced Crawling & Discovery
================================================================================
[*] Crawling: https://juice-shop.herokuapp.com (Depth: 0)
[*] Crawling: https://juice-shop.herokuapp.com/login (Depth: 1)
[*] Crawling: https://juice-shop.herokuapp.com/register (Depth: 1)
...
✅ Crawling complete: 156 links found

[+] PHASE 2: Vulnerability Testing
================================================================================
[+] Gathering server information...
  📌 Server: nginx/1.18.0
  📌 Powered By: Express

[+] Testing SQL Injection...
  📌 Testing 23 URLs with parameters
  🔴 SQL Injection: https://juice-shop.herokuapp.com/rest/products/search?q='
  📌 Payload: ' OR '1'='1

[+] Testing XSS...
  🔴 XSS: https://juice-shop.herokuapp.com/#/search?q=<script>alert("XSS")</script>
  📌 Payload: <script>alert("XSS")</script>

[+] Scanning ports...
  🌐 Port 443 open (HTTPS)
  🌐 Port 80 open (HTTP)
📚 Learning Resources
Recommended Practice Platforms
Platform	URL	Description
OWASP Juice Shop	https://juice-shop.herokuapp.com	Best free training site
HackTheBox	https://www.hackthebox.com	Professional platform
TryHackMe	https://tryhackme.com	Interactive learning
PentesterLab	https://pentesterlab.com	Hands-on exercises
Root-Me	https://www.root-me.org	Challenges & CTF
OverTheWire	https://overthewire.org	Wargames
VulnHub	https://www.vulnhub.com	Vuln VMs
PortSwigger	https://portswigger.net/web-security	Web security training
🤝 Contributing
We welcome contributions! If you want to improve Net Hat 3.3:

Fork the repository

Create your feature branch

Commit your changes

Push to the branch

Create a Pull Request

Report Issues
Open an issue on GitHub

Contact Developer: @JYI_L on Telegram

Include detailed error messages and steps to reproduce

📞 Contact & Support
Channel	Details
Developer	moshta3el
Telegram	@JYI_L
GitHub	moshta3el/Net-Hat-3.3
⭐ Support the Project
If you find this tool useful:

⭐ Star the repository

🔗 Share with fellow security enthusiasts

📝 Report any bugs or improvements

💡 Suggest new features

📜 License
Net Hat 3.3 is released under Ethical Use Only license:

✅ Allowed: Educational use, authorized penetration testing, personal projects

❌ Forbidden: Any illegal activity, unauthorized scanning, data theft, malicious use

text
⚠️ USE AT YOUR OWN RISK. THE DEVELOPER ASSUMES NO RESPONSIBILITY FOR ANY MISUSE.
<p align="center"> <b>Made with ❤️ by moshta3el | @JYI_L</b><br> <sub>For Ethical Hacking & Cyber Security Enthusiasts</sub> </p><p align="center"> <img src="https://img.shields.io/badge/Stay_Safe-Stay_Ethical-red?style=for-the-badge" alt="Stay Safe, Stay Ethical" /> <img src="https://img.shields.io/badge/Knowledge-Is_Power-blue?style=for-the-badge" alt="Knowledge Is Power" /> </p>
