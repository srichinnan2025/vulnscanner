import requests

# ---------------- XSS ----------------
def check_xss(url):
    findings = []
    payload = "<script>alert(1)</script>"
    test_url = url + "?xss=" + payload

    try:
        r = requests.get(test_url, timeout=5)

        if payload.lower() in r.text.lower():
            findings.append({
                "type": "XSS",
                "status": "Confirmed",
                "severity": "High",
                "cvss": 7.4,
                "url": test_url,
                "payload": payload,
                "description": "Reflected XSS confirmed (payload reflected)"
            })
        else:
            findings.append({
                "type": "XSS",
                "status": "Not Vulnerable",
                "severity": "Info",
                "cvss": 0.0,
                "url": url,
                "payload": payload,
                "description": "XSS payload tested but not reflected"
            })
    except:
        pass

    return findings

# ---------------- SQL Injection ----------------
def check_sqli(url):
    findings = []
    payloads = ["'", "\"", "' OR '1'='1"]
    sql_errors = [
        "sql syntax", "mysql", "syntax error",
        "unclosed quotation", "odbc", "pdo"
    ]

    try:
        normal = requests.get(url, timeout=5)
        normal_text = normal.text.lower()
    except:
        return findings

    potential = False

    for payload in payloads:
        test_url = url + payload
        try:
            r = requests.get(test_url, timeout=5)
            injected_text = r.text.lower()

            for err in sql_errors:
                if err in injected_text and err not in normal_text:
                    if injected_text != normal_text and r.status_code == 500:
                        findings.append({
                            "type": "SQL Injection",
                            "status": "Confirmed",
                            "severity": "High",
                            "cvss": 9.1,
                            "url": test_url,
                            "payload": payload,
                            "description": f"Confirmed SQL Injection using payload: {payload}"
                        })
                        return findings
                    else:
                        potential = True
        except:
            pass

    if potential:
        findings.append({
            "type": "SQL Injection",
            "status": "Potential / False Positive",
            "severity": "Medium",
            "cvss": 5.0,
            "url": url,
            "payload": "Tested",
            "description": "SQL error signs detected but not enough evidence (possible false positive)"
        })
    else:
        findings.append({
            "type": "SQL Injection",
            "status": "Not Vulnerable",
            "severity": "Info",
            "cvss": 0.0,
            "url": url,
            "payload": "N/A",
            "description": "SQL Injection tests did not trigger any database errors"
        })

    return findings

# ---------------- Clickjacking ----------------
def check_clickjacking(url):
    findings = []

    try:
        r = requests.get(url, timeout=5)
        xfo = r.headers.get("X-Frame-Options")

        if not xfo:
            findings.append({
                "type": "Clickjacking",
                "status": "Confirmed",
                "severity": "Medium",
                "cvss": 4.3,
                "url": url,
                "payload": "Missing",
                "description": "X-Frame-Options header is missing"
            })
        else:
            findings.append({
                "type": "Clickjacking",
                "status": "Not Vulnerable",
                "severity": "Info",
                "cvss": 0.0,
                "url": url,
                "payload": xfo,
                "description": f"X-Frame-Options present ({xfo})"
            })
    except:
        pass

    return findings
