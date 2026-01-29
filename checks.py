import requests

def check_xss(url):
    payload = "<script>alert(1)</script>"
    try:
        r = requests.get(url, params={"q": payload}, timeout=5)
        if payload in r.text:
            return {
                "type": "XSS",
                "status": "Vulnerable",
                "severity": "High",
                "cvss": "6.1",
                "owasp": "A03: Injection",
                "description": "Reflected XSS detected"
            }
    except:
        pass

    return {
        "type": "XSS",
        "status": "Not Vulnerable",
        "severity": "Info",
        "cvss": "0.0",
        "owasp": "A03: Injection",
        "description": "XSS payload not reflected"
    }


def check_sqli(url):
    payload = "' OR '1'='1"
    try:
        r = requests.get(url, params={"id": payload}, timeout=5)
        errors = ["sql", "mysql", "syntax", "warning"]
        if any(e in r.text.lower() for e in errors):
            return {
                "type": "SQL Injection",
                "status": "Vulnerable",
                "severity": "High",
                "cvss": "7.5",
                "owasp": "A03: Injection",
                "description": "SQL error message detected"
            }
    except:
        pass

    return {
        "type": "SQL Injection",
        "status": "Not Vulnerable",
        "severity": "Info",
        "cvss": "0.0",
        "owasp": "A03: Injection",
        "description": "No SQL indicators found"
    }


def check_clickjacking(url):
    try:
        r = requests.get(url, timeout=5)
        if "X-Frame-Options" not in r.headers:
            return {
                "type": "Clickjacking",
                "status": "Confirmed",
                "severity": "Medium",
                "cvss": "4.3",
                "owasp": "A05: Security Misconfiguration",
                "description": "X-Frame-Options header missing"
            }
    except:
        pass

    return {
        "type": "Clickjacking",
        "status": "Not Vulnerable",
        "severity": "Info",
        "cvss": "0.0",
        "owasp": "A05: Security Misconfiguration",
        "description": "Clickjacking protection enabled"
    }
