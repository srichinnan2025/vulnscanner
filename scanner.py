from datetime import datetime
from crawler import crawl
from checks import check_xss, check_sqli, check_clickjacking

def generate_report(findings, info):

    # -------- COUNTS (ALL) --------
    high = sum(1 for f in findings if f["severity"] == "High")
    medium = sum(1 for f in findings if f["severity"] == "Medium")
    low = sum(1 for f in findings if f["severity"] == "Low")
    info_c = sum(1 for f in findings if f["severity"] == "Info")

    total = high + medium + low

    with open("report.html", "w") as f:
        f.write(f"""
<html>
<head>
<title>Vulnerability Scan Report</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

<style>
body {{ font-family: Arial; }}
.summary {{ background:#f2f2f2; padding:15px; margin-bottom:20px; }}

table {{ width:100%; border-collapse:collapse; }}
th,td {{ border:1px solid #333; padding:8px; }}
th {{ background:#222; color:white; }}

.High {{ background:#ffd6d6; }}
.Medium {{ background:#ffe4b3; }}
.Low {{ background:#d6ffd6; }}
.Info {{ background:#eeeeee; }}

.badge-confirmed {{ background:red;color:white;padding:4px 8px;border-radius:6px; }}
.badge-potential {{ background:orange;color:black;padding:4px 8px;border-radius:6px; }}
.badge-not {{ background:gray;color:white;padding:4px 8px;border-radius:6px; }}
</style>
</head>

<body>

<h2>Vulnerability Scan Report</h2>

<div class="summary">
<b>Target:</b> {info['target']}<br>
<b>Start:</b> {info['start']}<br>
<b>End:</b> {info['end']}<br><br>

<b>Total Vulnerabilities:</b> {total}<br>
<b>High:</b> {high} |
<b>Medium:</b> {medium} |
<b>Low:</b> {low} |
<b>Info:</b> {info_c}
</div>


<br>

<table>
<tr>
<th>Type</th>
<th>Status</th>
<th>Severity</th>
<th>CVSS</th>
<th>URL</th>
<th>Payload</th>
<th>Description</th>
</tr>
""")

        for v in findings:
            if v["status"] == "Confirmed":
                badge = "<span class='badge-confirmed'>Confirmed</span>"
            elif "Potential" in v["status"]:
                badge = "<span class='badge-potential'>Potential</span>"
            else:
                badge = "<span class='badge-not'>Not Vulnerable</span>"

            f.write(f"""
<tr class="{v['severity']}">
<td>{v['type']}</td>
<td>{badge}</td>
<td>{v['severity']}</td>
<td>{v['cvss']}</td>
<td>{v['url']}</td>
<td><code>{v['payload']}</code></td>
<td>{v['description']}</td>
</tr>
""")

        f.write("</table></body></html>")

def main():
    target = input("Enter target URL: ").strip()
    start = datetime.now()

    findings = []
    for url in crawl(target):
        findings.extend(check_xss(url))
        findings.extend(check_sqli(url))
        findings.extend(check_clickjacking(url))

    generate_report(findings, {
        "target": target,
        "start": start,
        "end": datetime.now()
    })

    print("[+] Scan completed")
    print("[+] Report generated: report.html")

if __name__ == "__main__":
    main()
