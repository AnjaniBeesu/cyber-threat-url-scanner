from flask import Flask, render_template, request
from urllib.parse import urlparse
import re
app = Flask(__name__)
scan_count = 0
def analyze_url(url):
    score = 0
    reasons = []
    suspicious_words = [
        "login",
        "verify",
        "secure",
        "account",
        "bank",
        "update",
        "signin",
        "confirm",
        "password",
        "wallet"
    ]
    parsed = urlparse(url)
    # HTTPS Checking
    if parsed.scheme != "https":
        score += 20
        reasons.append(
            "The website is not using HTTPS encryption, making data transmission less secure."
        )
    # Suspicious Keywords
    for word in suspicious_words:
        if word in url.lower():
            score += 10
            reasons.append(
                f'The URL contains the suspicious keyword "{word}".'
            )
    # Long URL
    if len(url) > 75:
        score += 15
        reasons.append(
            "The URL is unusually long, which is common in phishing attempts."
        )
    # IP Address Detection
    ip_pattern = r"\d+\.\d+\.\d+\.\d+"
    if re.search(ip_pattern, parsed.netloc):
        score += 25
        reasons.append(
            "The website uses an IP address instead of a normal domain name."
        )
    # Too Many Subdomains
    if parsed.netloc.count('.') > 3:
        score += 15
        reasons.append(
            "The URL contains multiple subdomains which can be used to imitate trusted websites."
        )
    # Excessive Hyphens
    if parsed.netloc.count('-') > 3:
        score += 10
        reasons.append(
            "The domain contains an unusually high number of hyphens."
        )
    # Numbers in Domains
    if re.search(r"\d", parsed.netloc):
        score += 10
        reasons.append(
            "The domain contains numbers which can sometimes indicate impersonation."
        )
    # Typosquatting Detection
    fake_brands = {
        "g00gle": "Google",
        "paypa1": "PayPal",
        "arnazon": "Amazon",
        "micr0soft": "Microsoft",
        "faceb00k": "Facebook",
        "instagrarn": "Instagram",
        "githuh": "GitHub"
    }
    domain = parsed.netloc.lower()
    for fake, real in fake_brands.items():
        if fake in domain:
            score += 30
            reasons.append(
                f"The domain may be impersonating {real}."
            )
    score = min(score, 100)
    # Verdict
    if score >= 80:
        verdict = " EXTREMELY DANGEROUS"
    elif score >= 60:
        verdict = "Dangerous"
    elif score >= 40:
        verdict = " Suspicious"
    elif score >= 20:
        verdict = " Slightly Suspicious"
    else:
        verdict = " Safe"
    # Risk Bar Color
    if score <= 20:
        risk_color = "#22c55e"      # Green
    elif score <= 40:
        risk_color = "#84cc16"      # Yellow-Green
    elif score <= 60:
        risk_color = "#eab308"      # Yellow
    elif score <= 80:
        risk_color = "#f97316"      # Orange
    else:
        risk_color = "#ef4444"      # Red
    return score, verdict, reasons, risk_color
@app.route("/", methods=["GET", "POST"])
def home():
    global scan_count
    score = None
    verdict = None
    reasons = []
    risk_color = "#22c55e"
    if request.method == "POST":
        scan_count += 1
        url = request.form["url"]
        score, verdict, reasons, risk_color = analyze_url(url)
    return render_template(
        "index.html",
        score=score,
        verdict=verdict,
        reasons=reasons,
        risk_color=risk_color,
        scan_count=scan_count
    )
if __name__ == "__main__":
    app.run(debug=True)
