This tool scans raw text and extracts Indicators of Compromise (IOCs) including IP addresses, file hashes, and URLs. I tested it using a simulated malicious file (free-coffee.zip) from my SOC lab environment and found that it improves efficiency, minimizes missed indicators, and streamlines the investigation process.



import re

INPUT_FILE = "free-coffee.zip"

def extract_iocs():
    print("Starting IOC extraction...\n")

    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        content = f.read()

    # Patterns for common indicators
    ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
    hash_pattern = r"\b[a-fA-F0-9]{32,64}\b"
    url_pattern = r"https?://[^\s]+"

    ips = set(re.findall(ip_pattern, content))
    hashes = set(re.findall(hash_pattern, content))
    urls = set(re.findall(url_pattern, content))

    print("=== Results ===\n")

    if ips:
        print("IP Addresses:")
        for ip in ips:
            print(f"- {ip}")
    else:
        print("No IP addresses found.")

    print()

    if hashes:
        print("File Hashes:")
        for h in hashes:
            print(f"- {h}")
    else:
        print("No hashes found.")

    print()

    if urls:
        print("URLs:")
        for url in urls:
            print(f"- {url}")
    else:
        print("No URLs found.")


if __name__ == "__main__":
    extract_iocs()
