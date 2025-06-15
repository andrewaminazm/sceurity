 API Security Scanner GUI

A user-friendly Python-based GUI tool for scanning websites and APIs for common security issues.

🚀 Features

✅ Checks HTTPS enforcement

🧰 Validates presence of security headers

🌐 Verifies CORS policy configuration

🔎 Probes allowed HTTP methods

🗃️ Detects common sensitive files (e.g., .env, .git/config)

📁 Detects potential directory listing

🔓 Scans for open common ports

💉 Detects reflected injection vulnerabilities (SQLi, XSS, Command Injection)

📝 Custom payloads for injection testing

📄 Generates HTML + JSON security reports

⏰ Schedule weekly scans (background thread)

📅 Installation

pip install requests schedule

Python 3.7+ is recommended.

▶️ Usage

Run the tool:

python scanner_gui.py

Enter the website or API base URL (e.g., https://example.com).

Click Start Scan.

View detailed logs in the UI and HTML report in your browser.

Use Add Payload to define custom attack vectors.

Optionally schedule weekly scans (every Sunday 10:00 AM).

🔍 What It Tests For

1. HTTPS Check

Ensures the target uses secure HTTPS protocol.

2. Security Headers

Checks for these headers:

Content-Security-Policy

Strict-Transport-Security

X-Frame-Options

X-Content-Type-Options

Referrer-Policy

Permissions-Policy

3. CORS Policy

Validates if cross-origin resource sharing (CORS) is misconfigured.

4. HTTP Method Probing

Attempts to send requests with different HTTP methods (GET, POST, PUT, etc.).

5. Sensitive File Access

Scans for exposure of:

.env

.git/config

backup.zip

6. Directory Listing

Detects if web servers expose file directory listings.

7. Port Scan (Low-Noise)

Tests for open common ports: 21, 22, 80, 443, 8080, 3306

8. Reflected Injection Checks

Sends payloads to test basic vulnerability reflection (e.g., XSS, SQLi).

📊 Reports

After scan:

HTML Report: security_report.html

JSON Report: security_report.json

These are saved in the current directory and opened automatically.

📀 Sample Payloads to Add

You can use the Add Custom Payload feature to test for the following:

SQL Injection (SQLi)

' OR '1'='1

' UNION SELECT NULL, version() -- 

admin' --

Cross-Site Scripting (XSS)

<script>alert(1)</script>

"><img src=x onerror=alert(1)>

<svg/onload=alert('XSS')>

Command Injection

; ls -la

| whoami

& echo hacked

Path Traversal

../../../../etc/passwd

..\\..\\..\\boot.ini

SSRF

http://127.0.0.1:80

http://169.254.169.254/latest/meta-data/

