from flask import Flask, render_template, request
from datetime import datetime
from crawler import crawl
from scanner import run_scan

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    results = []
    status = ""
    scan_time = None

    if request.method == "POST":
        target = request.form["url"]

        status = "Crawling website..."
        urls = crawl(target)

        status = "Scanning URLs..."
        results = run_scan(urls)

        scan_time = datetime.now().strftime("%d-%m-%Y %I:%M:%S %p")
        status = "Scan completed successfully"

    return render_template(
        "dashboard.html",
        results=results,
        status=status,
        scan_time=scan_time
    )

if __name__ == "__main__":
    app.run(debug=True)
