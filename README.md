# 🔍 VulnScanner – Web Vulnerability Scanner

VulnScanner is a lightweight **Python-based web vulnerability scanning tool** designed to identify common security issues in web applications.  
It provides an easy-to-use interface with automated scanning and report generation.

---

## 🚀 Features

- 🔎 URL crawling and endpoint discovery  
- 🛡️ Basic vulnerability checks (custom rules)  
- 📊 HTML vulnerability report generation  
- 🌐 Simple web dashboard (Flask)  
- ⚡ Fast and beginner-friendly  

---

## 🧰 Tech Stack

- **Language:** Python 3  
- **Framework:** Flask  
- **Frontend:** HTML, CSS  
- **Environment:** Kali Linux / Linux  
- **Tools:** requests, BeautifulSoup (if used)

---

## 📁 Project Structure
vulnscanner/
│
├── app.py # Main Flask application
├── scanner.py # Core scanning logic
├── crawler.py # URL crawler
├── checks.py # Vulnerability checks
├── report.html # Scan report output
│
├── templates/
│ ├── index.html
│ └── dashboard.html
│
├── static/
│ └── style.css
│
├── .gitignore
└── README.md

---

## ⚙️ Installation

### 1️⃣ Clone the repository
```bash
git clone https://github.com/USERNAME/vulnscanner.git
cd vulnscanner
python3 -m venv venv
source venv/bin/activate
Install dependencies
pip install -r requirements.txt
Run the application:
python app.py
Open browser:
http://127.0.0.1:5000

📄 Output
Scan results displayed on dashboard
HTML report generated as report.html
Vulnerabilities categorized for easy understanding

⚠️ Disclaimer

This tool is developed for educational and ethical testing purposes only.
Do NOT scan websites without proper authorization.
The author is not responsible for misuse.

📌 Future Enhancements

OWASP Top 10 coverage
Authentication testing
Export reports (PDF / JSON)
Severity scoring
Docker support

👨‍💻 Author
Sri Priya C
Cyber Security Enthusiast | Ethical Hacking Learner









