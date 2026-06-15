# Login Page Detection Tool

## Overview

This Python tool is designed to analyze web page content and determine whether a given page is likely a **login interface**. Identifying login pages is a critical step in security operations, especially during phishing analysis, threat hunting, and web reconnaissance.

Attackers frequently create fake login pages to harvest credentials. Being able to quickly and programmatically detect such pages allows analysts to prioritize investigations, flag suspicious domains, and reduce response time in real-world SOC environments.

---


### Key Advantages

* **Speed** – Quickly identifies potential login pages without manual inspection
* **Consistency** – Uses defined indicators to avoid human error
* **Scalability** – Can be integrated into larger scripts or pipelines for bulk analysis
* **SOC Relevance** – Useful in phishing detection, alert triage, and threat intelligence workflows

---

## Detection Logic

The script evaluates the page content using several practical heuristics:

* Checks if the word **"Login"** (or similar phrases in different languages) exists on the page
* Detects the presence of **HTML `<form>` tags**, commonly used for authentication
* Searches for keywords such as **"username"** or **"password"** in input field placeholders
* Looks for login-related terms in the **page title or headers**

By combining these indicators, the tool provides a reasonable assessment of whether the page is a login interface.

---

## How It Works

1. The script sends an HTTP request to the target URL
2. It parses the HTML response
3. It evaluates the content against predefined login indicators
4. It outputs a result indicating whether the page is likely a login page

---

## Python Implementation

```python
import requests
from bs4 import BeautifulSoup

# Common login-related keywords in multiple languages
LOGIN_KEYWORDS = [
    "login", "sign in", "log in", "signin",
    "connexion", "iniciar sesión", "anmelden",
    "acceder", "ログイン", "登录"
]

USERNAME_KEYWORDS = ["username", "email", "user"]
PASSWORD_KEYWORDS = ["password", "pass", "pwd"]


def is_login_page(url):
    try:
        response = requests.get(url, timeout=10)
        content = response.text.lower()

        soup = BeautifulSoup(content, "html.parser")

        score = 0

        # 1. Check for login-related keywords in page text
        if any(keyword in content for keyword in LOGIN_KEYWORDS):
            score += 1

        # 2. Check for form tags
        forms = soup.find_all("form")
        if forms:
            score += 1

        # 3. Check input fields for username/password indicators
        inputs = soup.find_all("input")
        for inp in inputs:
            placeholder = (inp.get("placeholder") or "").lower()
            name = (inp.get("name") or "").lower()

            if any(k in placeholder or k in name for k in USERNAME_KEYWORDS):
                score += 1
                break

        for inp in inputs:
            placeholder = (inp.get("placeholder") or "").lower()
            name = (inp.get("name") or "").lower()

            if any(k in placeholder or k in name for k in PASSWORD_KEYWORDS):
                score += 1
                break

        # 4. Check title and headers
        title = soup.title.string.lower() if soup.title and soup.title.string else ""
        headers = " ".join([h.text.lower() for h in soup.find_all(["h1", "h2", "h3"])])

        if any(keyword in title or keyword in headers for keyword in LOGIN_KEYWORDS):
            score += 1

        # Final decision
        if score >= 3:
            return f"[+] {url} is likely a LOGIN page (score: {score})"
        else:
            return f"[-] {url} is unlikely to be a login page (score: {score})"

    except Exception as e:
        return f"[!] Error analyzing {url}: {str(e)}"


if __name__ == "__main__":
    target_url = input("Enter URL to analyze: ").strip()
    result = is_login_page(target_url)
    print(result)
```

---

## Conclusion

In short, by parsing the HTML response and evaluating indicators such as login-related keywords, form usage, and credential input fields, this script can efficiently identify most login pages. This makes it a practical tool that can be used to quickly assess web content during investigations.
