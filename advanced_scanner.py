import os
import requests
import time
import random
import logging
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from flask import Flask, request, render_template, jsonify, session, send_file
import datetime
import ssl
import urllib3
from urllib3.exceptions import InsecureRequestWarning
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from io import BytesIO
import concurrent.futures

urllib3.disable_warnings(InsecureRequestWarning)

app = Flask(__name__, template_folder="templates")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app.secret_key = os.environ.get('SECRET_KEY', 'default-secret-key')

class AdvancedVulnerabilityScanner:
    def __init__(self, target_url):
        parsed = urlparse(target_url)
        if not parsed.scheme or not parsed.netloc:
            raise ValueError("Invalid URL format")
        
        self.target_url = target_url if target_url.endswith('/') else target_url + '/'
        
        self.session = requests.Session()
        self.session.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "max-age=0",
            "DNT": "1"
        }
        
        self.session.verify = False
        self.cert_details = {}
        
        # Timeout & retry
        self.timeout = 30
        self.retries = 2
        self.delay = random.uniform(0.3, 1.0)
        
        self.vulnerabilities = []
        logger.info(f"Scanner initialized for: {self.target_url}")

    def safe_request(self, method, url, **kwargs):
        """Robust request handling with retries and delays"""
        for attempt in range(self.retries + 1):
            try:
                time.sleep(self.delay)
                
                if 'timeout' not in kwargs:
                    kwargs['timeout'] = self.timeout
                    
                kwargs['verify'] = False
                    
                response = self.session.request(method, url, **kwargs)
                response.raise_for_status()
                return response
            except requests.exceptions.SSLError as e:
                logger.error(f"SSL Error: {str(e)}")
                self.vulnerabilities.append({
                    "type": "SSL/TLS Issue",
                    "detail": f"SSL Error: {str(e)}"
                })
                return None
            except requests.exceptions.RequestException as e:
                logger.warning(f"Request failed (attempt {attempt+1}/{self.retries+1}): {str(e)}")
                if attempt < self.retries:
                    wait_time = 2 ** attempt  
                    logger.info(f"Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
                else:
                    logger.error(f"Request failed for {url}: {str(e)}")
                    return None
            except Exception as e:
                logger.error(f"Unexpected error: {str(e)}")
                return None

    def load_wordlist(self, path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            logger.error(f"Wordlist not found: {path}")
            return []
        except Exception as e:
            logger.error(f"Error loading wordlist: {e}")
            return []

    def get_all_forms(self, url):
        try:
            logger.info(f"Fetching forms from: {url}")
            res = self.safe_request('GET', url)
            if res is None or res.status_code != 200:
                return []
                
            soup = BeautifulSoup(res.content, "html.parser")
            forms = soup.find_all("form")
            logger.info(f"Found {len(forms)} forms")
            return forms
        except Exception as e:
            logger.error(f"Error getting forms: {e}")
            return []

    def submit_form(self, form, payload, url):
        try:
            action = form.attrs.get("action", "").lower()
            method = form.attrs.get("method", "get").lower()
            inputs = form.find_all("input")
            form_data = {}
            
            for input in inputs:
                name = input.attrs.get("name")
                input_type = input.attrs.get("type", "text")
                value = input.attrs.get("value", "")
                if input_type in ["text", "search", "password", "email", "number"]:
                    value = payload
                if name:
                    form_data[name] = value
            
            target = urljoin(url, action)
            logger.info(f"Submitting form to: {target} with method: {method}")
            
            if method == "post":
                return self.safe_request('POST', target, data=form_data)
            return self.safe_request('GET', target, params=form_data)
        except Exception as e:
            logger.error(f"Error submitting form: {e}")
            return None

    # Vulnerability
    def check_xss(self):
        try:
            logger.info("Starting XSS check")
            payloads = self.load_wordlist("wordlists/xss.txt") or []
            if not payloads:
                return
                
            forms = self.get_all_forms(self.target_url)
            vulnerability_found = False
            
            for payload in payloads:
                if vulnerability_found:
                    break
                    
                for form in forms:
                    res = self.submit_form(form, payload, self.target_url)
                    if res and res.status_code == 200 and payload in res.text:
                        self.vulnerabilities.append({"type": "XSS", "payload": payload})
                        vulnerability_found = True
                        break
        except Exception as e:
            logger.error(f"XSS check failed: {e}")
        finally:
            logger.info("Completed XSS check")

    def check_sql_injection(self):
        try:
            logger.info("Starting SQL Injection check")
            payloads = self.load_wordlist("wordlists/sqli.txt") or []
            if not payloads:
                return
                
            errors = ["sql syntax", "mysql_fetch", "ORA-", "unclosed quotation", "syntax error"]
            forms = self.get_all_forms(self.target_url)
            vulnerability_found = False
            
            for payload in payloads:
                if vulnerability_found:
                    break
                    
                for form in forms:
                    res = self.submit_form(form, payload, self.target_url)
                    if res and res.status_code == 200 and any(err in res.text.lower() for err in errors):
                        self.vulnerabilities.append({"type": "SQL Injection", "payload": payload})
                        vulnerability_found = True
                        break
        except Exception as e:
            logger.error(f"SQL Injection check failed: {e}")
        finally:
            logger.info("Completed SQL Injection check")

    def check_csrf(self):
        try:
            logger.info("Starting CSRF check")
            forms = self.get_all_forms(self.target_url)
            csrf_vulnerable = False
            
            for form in forms:
                inputs = form.find_all("input")
                if not any("csrf" in (i.attrs.get("name") or "").lower() for i in inputs):
                    csrf_vulnerable = True
                    break
            
            if csrf_vulnerable:
                self.vulnerabilities.append({"type": "CSRF", "detail": "Forms missing CSRF token"})
        except Exception as e:
            logger.error(f"CSRF check failed: {e}")
        finally:
            logger.info("Completed CSRF check")

    def check_command_injection(self):
        try:
            logger.info("Starting Command Injection check")
            payloads = self.load_wordlist("wordlists/command_injection.txt") or []
            if not payloads:
                return
                
            indicators = ["uid=", "gid=", "root", "user"]
            forms = self.get_all_forms(self.target_url)
            vulnerability_found = False
            
            for payload in payloads:
                if vulnerability_found:
                    break
                    
                for form in forms:
                    res = self.submit_form(form, payload, self.target_url)
                    if res and res.status_code == 200 and any(ind in res.text.lower() for ind in indicators):
                        self.vulnerabilities.append({"type": "Command Injection", "payload": payload})
                        vulnerability_found = True
                        break
        except Exception as e:
            logger.error(f"Command Injection check failed: {e}")
        finally:
            logger.info("Completed Command Injection check")

    def check_directory_traversal(self):
        try:
            logger.info("Starting Directory Traversal check")
            payloads = self.load_wordlist("wordlists/directory_traversal.txt") or []
            if not payloads:
                return
                
            vulnerability_found = False
            
            for payload in payloads:
                if vulnerability_found:
                    break
                    
                res = self.safe_request('GET', self.target_url + payload)
                if res and res.status_code == 200 and ("root:x" in res.text or "[extensions]" in res.text):
                    self.vulnerabilities.append({"type": "Directory Traversal", "payload": payload})
                    vulnerability_found = True
        except Exception as e:
            logger.error(f"Directory Traversal check failed: {e}")
        finally:
            logger.info("Completed Directory Traversal check")

    def check_open_redirect(self):
        try:
            logger.info("Starting Open Redirect check")
            payloads = self.load_wordlist("wordlists/open_redirect.txt") or []
            if not payloads:
                return
                
            vulnerability_found = False
            
            for payload in payloads:
                if vulnerability_found:
                    break
                    
                redirect_url = f"{self.target_url}?next={payload}"
                res = self.safe_request('GET', redirect_url, allow_redirects=False)
                if res and res.status_code in [301, 302] and payload in res.headers.get("Location", ""):
                    self.vulnerabilities.append({"type": "Open Redirect", "payload": payload})
                    vulnerability_found = True
        except Exception as e:
            logger.error(f"Open Redirect check failed: {e}")
        finally:
            logger.info("Completed Open Redirect check")

    def check_auth_bypass(self):
        try:
            logger.info("Starting Auth Bypass check")
            paths = self.load_wordlist("wordlists/auth_bypass.txt") or []
            if not paths:
                return
                
            vulnerability_found = False
            
            for path in paths:
                if vulnerability_found:
                    break
                    
                url = urljoin(self.target_url, path)
                res = self.safe_request('GET', url)
                if res and res.status_code == 200 and ("Welcome" in res.text or "admin" in res.text or "dashboard" in res.text):
                    self.vulnerabilities.append({"type": "Auth Bypass", "url": path})
                    vulnerability_found = True
        except Exception as e:
            logger.error(f"Auth Bypass check failed: {e}")
        finally:
            logger.info("Completed Auth Bypass check")

    def check_security_headers(self):
        try:
            logger.info("Starting Security Headers check")
            res = self.safe_request('GET', self.target_url)
            if res:
                headers = ["X-Frame-Options", "Content-Security-Policy", "X-XSS-Protection", "Strict-Transport-Security"]
                missing_headers = [h for h in headers if h not in res.headers]
                
                if missing_headers:
                    self.vulnerabilities.append({
                        "type": "Missing Security Headers", 
                        "detail": f"Missing: {', '.join(missing_headers)}"
                    })
        except Exception as e:
            logger.error(f"Security Headers check failed: {e}")
        finally:
            logger.info("Completed Security Headers check")

    def check_info_disclosure(self):
        try:
            logger.info("Starting Info Disclosure check")
            paths = self.load_wordlist("wordlists/info_disclosure_paths.txt") or []
            if not paths:
                return
                
            vulnerability_found = False
            
            for path in paths:
                if vulnerability_found:
                    break
                    
                url = urljoin(self.target_url, path)
                res = self.safe_request('GET', url)
                if res and res.status_code == 200 and any(ext in path for ext in [".git", ".svn", ".bak", ".zip", ".env", ".DS_Store"]):
                    self.vulnerabilities.append({"type": "Info Disclosure", "url": path})
                    vulnerability_found = True
        except Exception as e:
            logger.error(f"Info Disclosure check failed: {e}")
        finally:
            logger.info("Completed Info Disclosure check")

    def check_crlf_injection(self):
        try:
            logger.info("Starting CRLF Injection check")
            payloads = self.load_wordlist("wordlists/crlf.txt") or []
            if not payloads:
                return
                
            vulnerability_found = False
            
            for payload in payloads:
                if vulnerability_found:
                    break
                    
                res = self.safe_request('GET', self.target_url + payload)
                if res and "injected" in res.headers.get("Set-Cookie", ""):
                    self.vulnerabilities.append({"type": "CRLF Injection", "payload": payload})
                    vulnerability_found = True
        except Exception as e:
            logger.error(f"CRLF Injection check failed: {e}")
        finally:
            logger.info("Completed CRLF Injection check")

    def check_ssl_issues(self):
        try:
            logger.info("Starting SSL/TLS check")
            hostname = urlparse(self.target_url).hostname
            port = 443
            
            try:
                cert = ssl.get_server_certificate((hostname, port))
                logger.info(f"SSL certificate found for {hostname}")
            except Exception as e:
                logger.error(f"SSL certificate error: {str(e)}")
                self.vulnerabilities.append({
                    "type": "SSL/TLS Issue",
                    "detail": f"Certificate error: {str(e)}"
                })
                
        except Exception as e:
            logger.error(f"SSL check failed: {e}")
        finally:
            logger.info("Completed SSL/TLS check")

    def check_clickjacking(self):
        """Detect if the site is vulnerable to clickjacking attacks"""
        try:
            logger.info("Starting Clickjacking check")
            res = self.safe_request('GET', self.target_url)
            if not res:
                return
                
            headers = res.headers
            
            x_frame_options = headers.get('X-Frame-Options', '').lower()
            csp_header = headers.get('Content-Security-Policy', '').lower()
            
            csp_frame_protection = "frame-ancestors" in csp_header and (
                "'none'" in csp_header or "'self'" in csp_header
            )
            
            vulnerable = False
            protection_details = []
            
            if x_frame_options:
                if x_frame_options in ['deny', 'sameorigin']:
                    protection_details.append(f"X-Frame-Options: {x_frame_options}")
                else:
                    vulnerable = True
                    protection_details.append(f"Invalid X-Frame-Options value: {x_frame_options}")
            else:
                vulnerable = True
                protection_details.append("X-Frame-Options header missing")
                
            if csp_frame_protection:
                protection_details.append("CSP frame-ancestors protection present")
            elif "frame-ancestors" in csp_header:
                vulnerable = True
                protection_details.append(f"Insecure CSP frame-ancestors: {csp_header}")
            else:
                vulnerable = True
                protection_details.append("CSP frame-ancestors protection missing")
                
            if vulnerable:
                self.vulnerabilities.append({
                    "type": "Clickjacking",
                    "detail": "Site is vulnerable to clickjacking attacks",
                    "protection": " | ".join(protection_details)
                })
            else:
                logger.info("Clickjacking protections are in place")
                
        except Exception as e:
            logger.error(f"Clickjacking check failed: {e}")
        finally:
            logger.info("Completed Clickjacking check")

    def scan(self):
        logger.info(f"Starting scan of: {self.target_url}")
        start_time = time.time()
        
        checks = [
            self.check_ssl_issues,
            self.check_security_headers,
            self.check_clickjacking,
            self.check_open_redirect,
            self.check_info_disclosure,
            self.check_csrf,
            self.check_xss,
            self.check_sql_injection,
            self.check_command_injection,
            self.check_directory_traversal,
            self.check_crlf_injection,
            self.check_auth_bypass
        ]
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
            futures = [executor.submit(check) for check in checks]
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    logger.error(f"Check failed: {e}")

        scan_duration = time.time() - start_time
        logger.info(f"Scan completed in {scan_duration:.2f} seconds. Found {len(self.vulnerabilities)} vulnerabilities")
        return self.vulnerabilities

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/scan', methods=['POST'])
def scan_api():
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({"error": "URL missing"}), 400
            
        logger.info(f"Starting scan for: {data['url']}")
        scanner = AdvancedVulnerabilityScanner(data['url'])
        vulnerabilities = scanner.scan()
        
        session['vulnerabilities'] = vulnerabilities
        session['scan_url'] = data['url']
        session['scan_time'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        session['investigator'] = data.get('investigator', 'Unknown')
        
        logger.info(f"Scan completed. Found {len(vulnerabilities)} vulnerabilities")
        return jsonify({
            "redirect": "/results"
        })
        
    except Exception as e:
        logger.error(f"Scan failed: {str(e)}", exc_info=True)
        return jsonify({
            "error": "Scan failed",
            "details": str(e)
        }), 500

@app.route('/results')
def results():
    return render_template(
        "results.html",
        vulnerabilities=session.get('vulnerabilities', []),
        scan_url=session.get('scan_url', 'Unknown URL'),
        scan_time=session.get('scan_time', 'Unknown time')
    )

@app.route('/download_report')
def download_report():
    try:
        vulnerabilities = session.get('vulnerabilities', [])
        scan_url = session.get('scan_url', 'Unknown URL')
        scan_time = session.get('scan_time', 'Unknown time')
        investigator = session.get('investigator', 'Unknown Investigator')
        report_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(
            name='ReportTitle',
            fontSize=18,
            alignment=TA_CENTER,
            spaceAfter=12
        ))
        styles.add(ParagraphStyle(
            name='ReportSubtitle',
            fontSize=12,
            textColor=colors.grey,
            alignment=TA_CENTER,
            spaceAfter=24
        ))
        styles.add(ParagraphStyle(
            name='ReportSectionHeader',
            fontSize=14,
            spaceBefore=12,
            spaceAfter=6
        ))
        styles.add(ParagraphStyle(
            name='ReportVulnHeader',
            fontSize=12,
            textColor=colors.red,
            spaceAfter=3
        ))
        styles.add(ParagraphStyle(
            name='ReportVulnDetail',
            fontSize=10,
            spaceAfter=9
        ))
        styles.add(ParagraphStyle(
            name='ReportFooter',
            fontSize=8,
            textColor=colors.grey
        ))
        
        elements = []
        
        elements.append(Paragraph("VULNERABILITY ASSESSMENT REPORT", styles['ReportTitle']))
        elements.append(Paragraph(f"Generated on {report_time}", styles['ReportSubtitle']))
        
        summary_data = [
            ["Target URL", scan_url],
            ["Scan Date/Time", scan_time],
            ["Report Date/Time", report_time],
            ["Investigator", investigator],
            ["Total Vulnerabilities", str(len(vulnerabilities))]]
        
        summary_table = Table(summary_data, colWidths=[150, 350])
        summary_table.setStyle(TableStyle([
            ('FONT', (0, 0), (-1, -1), 'Helvetica', 10),
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(summary_table)
        elements.append(Spacer(1, 24))
        
        
        if vulnerabilities:
            elements.append(Paragraph("VULNERABILITY FINDINGS", styles['ReportSectionHeader']))
            
            for idx, vuln in enumerate(vulnerabilities, 1):
                # severity level
                if vuln['type'] in ['SQL Injection', 'Command Injection', 'Directory Traversal']:
                    severity = "High"
                elif vuln['type'] in ['XSS', 'Auth Bypass', 'CRLF Injection']:
                    severity = "Medium"
                elif vuln['type'] in ['Missing Security Headers', 'Clickjacking']:
                    severity = "Low"
                else:
                    severity = "Info"
                
                elements.append(Paragraph(f"{idx}. {vuln['type']} - {severity} Risk", styles['ReportVulnHeader']))
                
                details = []
                if vuln.get('payload'):
                    details.append(f"Payload: {vuln['payload']}")
                if vuln.get('url'):
                    details.append(f"Path: {vuln['url']}")
                if vuln.get('detail'):
                    details.append(f"Details: {vuln['detail']}")
                if vuln.get('protection'):
                    details.append(f"Protection Status: {vuln['protection']}")
                
                for detail in details:
                    elements.append(Paragraph(detail, styles['ReportVulnDetail']))
                
                elements.append(Spacer(1, 12))
        else:
            elements.append(Paragraph("NO VULNERABILITIES FOUND", styles['ReportSectionHeader']))
            elements.append(Paragraph("No security vulnerabilities were detected during this scan.", styles['ReportVulnDetail']))
        
        elements.append(Spacer(1, 36))
        elements.append(Paragraph(f"Report generated by Advanced Vulnerability Scanner", styles['ReportFooter']))
        elements.append(Paragraph(f"Generated on {report_time}", styles['ReportFooter']))
        
        doc.build(elements)
        
        buffer.seek(0)
        filename = f"Vulnerability_Report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        
        return send_file(
            buffer,
            as_attachment=True,
            download_name=filename,
            mimetype='application/pdf'
        )
    except Exception as e:
        logger.error(f"Failed to generate report: {str(e)}")
        return jsonify({"error": "Report generation failed", "details": str(e)}), 500

debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
port = int(os.environ.get("PORT", 5000))
    
if debug_mode:
    logging.getLogger().setLevel(logging.DEBUG)
else:
    logging.getLogger().setLevel(logging.INFO)
    
app.run(debug=debug_mode, host='0.0.0.0', port=port)
# creator = suyash khare