import requests
from bs4 import BeautifulSoup
import re
import json

def check_https(url):
    return url.startswith("https://")

def get_headers(url):
    try:
        r = requests.get(url, timeout=5)
        return r.headers, r
    except:
        return None, None

def check_security_headers(headers):
    required = [
        "Content-Security-Policy",
        "X-Frame-Options",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "Referrer-Policy"
    ]
    return {h: (h in headers) for h in required}

def check_forms_https(soup):
    forms = soup.find_all("form")
    issues = []
    for f in forms:
        action = f.get("action", "")
        if action and not action.startswith("https://"):
            issues.append(action)
    return issues

def check_cookies(response):
    cookies = response.cookies
    issues = []
    for cookie in cookies:
        if not cookie.secure:
            issues.append(f"Cookie {cookie.name} without Secure flag")
        # HttpOnly cannot be detected with requests reliably
    return issues

def scan_html(html):
    issues = []
    findings = {
        "password_keywords": re.findall(r"(password|secret|token|api_key)", html, re.I),
        "software_versions": re.findall(r"\b[A-Za-z]+ [0-9]+\.[0-9\.]+", html)
    }
    return findings

def generate_report(result, output="report.json"):
    with open(output, "w") as f:
        json.dump(result, f, indent=4)

def easywebaudit(url):
    result = {
        "url": url,
        "uses_https": check_https(url)
    }

    headers, response = get_headers(url)
    if not headers:
        result["error"] = "Could not fetch URL."
        return result

    result["security_headers"] = check_security_headers(headers)

    soup = BeautifulSoup(response.text, "html.parser")

    result["forms_insecure"] = check_forms_https(soup)
    result["cookie_issues"] = check_cookies(response)
    result["html_findings"] = scan_html(response.text)

    return result

if __name__ == "__main__":
    url = input("Podaj URL: ")
    report = easywebaudit(url)
    generate_report(report)
    print("Skan zakończony. Raport zapisany w report.json")