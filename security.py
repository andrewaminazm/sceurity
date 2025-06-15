import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import requests
import socket
import threading
import json
import time
import schedule
from urllib.parse import urlparse
import webbrowser
import os

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]

class SecurityScannerGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("🛡️ API Security Scanner GUI")

        # URL Entry
        ttk.Label(master, text="🔗 Enter Website URL:").pack(pady=5)
        self.url_entry = ttk.Entry(master, width=60)
        self.url_entry.pack()

        # Tabs
        self.notebook = ttk.Notebook(master)
        self.output_text = tk.Text(self.notebook, wrap=tk.WORD, height=20)
        self.output_text.pack()
        self.notebook.add(self.output_text, text="Scan Logs")
        self.notebook.pack(expand=1, fill='both')

        # Buttons
        button_frame = ttk.Frame(master)
        button_frame.pack(pady=10)
        ttk.Button(button_frame, text="▶ Start Scan", command=self.start_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="🕒 Schedule Weekly Scan", command=self.schedule_weekly_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="➕ Add Payload", command=self.add_custom_payload).pack(side=tk.LEFT, padx=5)

        self.custom_payloads = {
            "SQL Injection": "' OR '1'='1",
            "Command Injection": "; ls",
            "XSS": "<script>alert(1)</script>"
        }

    def log(self, message):
        self.output_text.insert(tk.END, f"{message}\n")
        self.output_text.see(tk.END)

    def check_https(self, url):
        return url.lower().startswith("https://")

    def check_security_headers(self, url):
        try:
            headers = {'User-Agent': 'Mozilla/5.0'}
            resp = requests.get(url, headers=headers, timeout=10)
            return {h: resp.headers.get(h, "Missing") for h in SECURITY_HEADERS}
        except Exception as e:
            return {h: f"Error: {str(e)}" for h in SECURITY_HEADERS}

    def check_cors(self, url):
        try:
            headers = {'Origin': 'http://evil.com', 'User-Agent': 'Mozilla/5.0'}
            r = requests.get(url, headers=headers)
            return r.headers.get("Access-Control-Allow-Origin", "Missing or Not Set")
        except Exception as e:
            return f"Error: {str(e)}"

    def probe_http_methods(self, url):
        methods = ["GET", "POST", "PUT", "DELETE", "OPTIONS"]
        result = {}
        for method in methods:
            try:
                r = requests.request(method, url, timeout=5)
                result[method] = r.status_code
            except Exception as e:
                result[method] = f"Error: {str(e)}"
        return result

    def check_sensitive_files(self, url):
        paths = [".env", ".git/config", "backup.zip"]
        results = {}
        for path in paths:
            full_url = f"{url.rstrip('/')}/{path}"
            try:
                r = requests.get(full_url, timeout=5)
                results[path] = "Exposed!" if r.status_code == 200 else "Not Found"
            except Exception as e:
                results[path] = f"Error: {str(e)}"
        return results

    def check_directory_listing(self, url):
        try:
            r = requests.get(url, timeout=5)
            if "Index of" in r.text:
                return "Possible Directory Listing!"
            return "Not Found"
        except Exception as e:
            return f"Error: {str(e)}"

    def port_scan(self, hostname):
        ports = [21, 22, 80, 443, 3306, 8080]
        open_ports = []
        for port in ports:
            try:
                with socket.create_connection((hostname, port), timeout=1):
                    open_ports.append(port)
            except:
                pass
        return open_ports

    def check_injection_points(self, url):
        results = {}
        for name, payload in self.custom_payloads.items():
            try:
                test_url = f"{url}?test={payload}"
                r = requests.get(test_url, timeout=5)
                if payload.lower() in r.text.lower():
                    results[name] = "Potential Reflection Found!"
                else:
                    results[name] = "Clean"
            except Exception as e:
                results[name] = f"Error: {str(e)}"
        return results

    def generate_html_report(self, report, filename="security_report.html"):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        with open(filename, "w", encoding="utf-8") as f:
            f.write(f"""
            <html><head>
            <link rel='stylesheet' href='https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css'>
            <title>Security Report</title></head><body class='p-4'>
            <h2>Security Scan Report <small class='text-muted'>{timestamp}</small></h2><hr>
            """)
            for section, data in report.items():
                f.write(f"<h4>{section}</h4><pre>{json.dumps(data, indent=4)}</pre><hr>")
            f.write("</body></html>")
        return filename

    def export_json(self, report):
        with open("security_report.json", "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4)

    def scan(self, url):
        try:
            if not url.startswith("http"):
                url = "https://" + url

            host = urlparse(url).hostname
            self.log(f"🔍 Scanning {url}...")

            report = {
                "URL": url,
                "HTTPS Enabled": self.check_https(url),
                "Security Headers": self.check_security_headers(url),
                "CORS Policy": self.check_cors(url),
                "Allowed HTTP Methods": self.probe_http_methods(url),
                "Sensitive Files": self.check_sensitive_files(url),
                "Directory Listing": self.check_directory_listing(url),
                "Open Ports": self.port_scan(host),
                "Injection Points": self.check_injection_points(url)
            }

            self.log("✅ Scan Complete. Report Generated.")
            self.log(json.dumps(report, indent=2))

            file_path = self.generate_html_report(report)
            self.export_json(report)
            self.log(f"📁 HTML Report: {file_path}")
            webbrowser.open(f"file://{os.path.abspath(file_path)}")

        except Exception as e:
            self.log(f"❌ Scan Failed: {str(e)}")

    def start_scan(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("Input Error", "Please enter a website URL.")
            return
        threading.Thread(target=self.scan, args=(url,), daemon=True).start()

    def schedule_weekly_scan(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("Input Error", "Enter a URL to schedule.")
            return

        def job():
            self.log("⏰ Scheduled weekly scan running...")
            self.scan(url)

        schedule.every().sunday.at("10:00").do(job)
        threading.Thread(target=lambda: self.run_schedule(), daemon=True).start()
        self.log("📅 Weekly scan scheduled for every Sunday at 10:00 AM.")

    def run_schedule(self):
        while True:
            schedule.run_pending()
            time.sleep(60)

    def add_custom_payload(self):
        inj_type = simpledialog.askstring("Injection Type", "Enter Injection Type:")
        payload = simpledialog.askstring("Payload", f"Enter payload for {inj_type}:")
        if inj_type and payload:
            self.custom_payloads[inj_type] = payload
            self.log(f"Added: {inj_type} => {payload}")


if __name__ == '__main__':
    root = tk.Tk()
    app = SecurityScannerGUI(root)
    root.mainloop()
