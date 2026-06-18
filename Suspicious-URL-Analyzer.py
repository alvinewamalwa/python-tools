
## Overview

This tool is designed to analyze a given URL and determine whether it exhibits characteristics commonly associated with phishing or malicious activity. It is particularly useful during alert triage and threat intelligence investigations where analysts need to quickly assess the legitimacy of URLs.

In many real-world scenarios, attackers craft deceptive URLs that mimic trusted domains, use obfuscation techniques, or attempt to mislead users into revealing sensitive information. This script automates the detection of such indicators to support faster and more consistent decision-making.

---

### Key Advantages

* **Fast analysis** of suspicious URLs
* **Consistent detection logic** across investigations
* **Supports SOC workflows** such as phishing analysis and alert validation
* **Lightweight and easy to integrate** into larger scripts

---

## Detection Logic

The script evaluates a URL based on several heuristics:

* Presence of an **IP address instead of a domain name**
* Excessive **length or complexity** of the URL
* Use of **special characters** such as `@`, `-`, or multiple subdomains
* Detection of **suspicious keywords** (e.g., login, verify, secure, update)
* Whether the URL uses **HTTP instead of HTTPS**
* Number of **dots/subdomains**, which may indicate obfuscation

Each indicator contributes to a score used to classify the URL.

---

## Python Implementation

```python
import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "bank", "password"
]

def has_ip_address(url):
    return re.search(r"http[s]?://\d+\.\d+\.\d+\.\d+", url) is not None

def analyze_url(url):
    score = 0
    parsed = urlparse(url)

    # 1. Check for IP address in URL
    if has_ip_address(url):
        score += 2

    # 2. Check URL length
    if len(url) > 75:
        score += 1

    # 3. Check for suspicious keywords
    if any(keyword in url.lower() for keyword in SUSPICIOUS_KEYWORDS):
        score += 1

    # 4. Check for excessive subdomains
    if parsed.netloc.count('.') > 3:
        score += 1

    # 5. Check for special characters
    if '@' in url or '-' in parsed.netloc:
        score += 1

    # 6. Check for HTTP instead of HTTPS
    if parsed.scheme == "http":
        score += 1

    # Final classification
    if score >= 4:
        return f"[!] HIGH RISK: {url} (score: {score})"
    elif score >= 2:
        return f"[!] SUSPICIOUS: {url} (score: {score})"
    else:
        return f"[+] LIKELY SAFE: {url} (score: {score})"


if __name__ == "__main__":
    target = input("Enter URL to analyze: ").strip()
    print(analyze_url(target))
```

---

## Example Output

* `[!] HIGH RISK: http://192.168.1.1/login-update (score: 5)`
* `[!] SUSPICIOUS: http://secure-account-login.example.com (score: 3)`
* `[+] LIKELY SAFE: https://www.google.com (score: 0)`

---



