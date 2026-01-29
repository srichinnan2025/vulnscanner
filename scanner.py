from checks import (
    check_xss,
    check_sqli,
    check_clickjacking
)

def run_scan(urls, progress_callback=None):
    """
    urls: list of URLs from crawler
    progress_callback: function to update progress message
    """

    all_results = []
    total = len(urls)

    for index, url in enumerate(urls, start=1):

        # 🔄 Progress update
        if progress_callback:
            progress_callback(f"Scanning {index}/{total} : {url}")

        findings = []

        # 🔍 Run vulnerability checks
        findings.append(check_xss(url))
        findings.append(check_sqli(url))
        findings.append(check_clickjacking(url))

        # 📦 Store results
        all_results.append({
            "url": url,
            "findings": findings
        })

    # ✅ Final progress
    if progress_callback:
        progress_callback("Scan completed successfully")

    return all_results
