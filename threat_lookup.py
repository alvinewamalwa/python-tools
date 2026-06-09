Threat Intel Lookup Tool 

This script lets you quickly check:

IP reputation
Domain info
File hash (VirusTotal-style lookup concept)


Note: This tool requires a VirusTotal API key. For security reasons, the key is not included in this repository.

import requests

VT_API_KEY = 

def check_ip(ip):
    url = "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8"
    headers = {"x-apikey": VT_API_KEY}
    
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        print(f"\n[IP RESULT] {ip}")
        print(f"Malicious: {stats['malicious']}")
        print(f"Suspicious: {stats['suspicious']}")
        print(f"Harmless: {stats['harmless']}")
    else:
        print("Error fetching IP data")

def check_hash(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}
    
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        print(f"\n[HASH RESULT] {file_hash}")
        print(f"Malicious: {stats['malicious']}")
        print(f"Suspicious: {stats['suspicious']}")
        print(f"Harmless: {stats['harmless']}")
    else:
        print("Error fetching hash data")

def main():
    print("=== Threat Intelligence Lookup Tool ===")
    choice = input("Check (1) IP or (2) Hash: ")

    if choice == "1":
        ip = input("Enter IP: ")
        check_ip(ip)
    elif choice == "2":
        file_hash = input("Enter file hash: ")
        check_hash(file_hash)
    else:
        print("Invalid option")

if __name__ == "__main__":
    main()
