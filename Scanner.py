import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup

class VulnerabilityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"
        self.vulnerabilities = []

    def get_all_forms(self):
        """Retrieve all forms from the target URL"""
        res = self.session.get(self.target_url)
        soup = BeautifulSoup(res.content, "html.parser")
        return soup.find_all("form")

    def submit_form(self, form, payload):
        """Submit form with modified inputs containing payload"""
        action = form.attrs.get("action", "").lower()
        method = form.attrs.get("method", "get").lower()
        inputs = form.find_all("input")
        
        form_data = {}
        for input in inputs:
            name = input.attrs.get("name")
            type = input.attrs.get("type", "text")
            value = input.attrs.get("value", "")
            if type == "text":
                value = payload
            
            if name:
                form_data[name] = value
        
        target_url = urljoin(self.target_url, action)
        
        if method == "post":
            return self.session.post(target_url, data=form_data)
        else:
            return self.session.get(target_url, params=form_data)

    def test_xss(self):
        """Test for XSS vulnerabilities"""
        xss_payload = "<script>alert('XSS');</script>"
        forms = self.get_all_forms()
        
        for form in forms:
            response = self.submit_form(form, xss_payload)
            if xss_payload in response.text:
                self.vulnerabilities.append({
                    "type": "XSS",
                    "form": form,
                    "payload": xss_payload
                })
                print(f"[!] XSS vulnerability detected in form:")
                print(form)
                print("="*50)

    def test_sql_injection(self):
        """Test for SQL Injection vulnerabilities"""
        sql_payload = "' OR 1=1 -- "
        error_keywords = ["sql syntax", "syntax error", "mysql", "ora-", "unclosed quotation mark"]
        forms = self.get_all_forms()
        
        for form in forms:
            response = self.submit_form(form, sql_payload)
            content = response.text.lower()
            for keyword in error_keywords:
                if keyword in content:
                    self.vulnerabilities.append({
                        "type": "SQL Injection",
                        "form": form,
                        "payload": sql_payload
                    })
                    print(f"[!] Potential SQL Injection vulnerability detected in form:")
                    print(form)
                    print("="*50)
                    break

    def scan(self):
        """Run all security tests"""
        print(f"[*] Scanning {self.target_url}")
        self.test_xss()
        self.test_sql_injection()
        
        if not self.vulnerabilities:
            print("[+] No vulnerabilities found")
        else:
            print(f"\n[+] Found {len(self.vulnerabilities)} potential vulnerabilities")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python scanner.py <target_url>")
        sys.exit(1)
    
    target_url = sys.argv[1]
    scanner = VulnerabilityScanner(target_url)
    scanner.scan()