## File Integrity Monitor (FIM)

## Overview

This tool monitors files for unauthorized changes by generating and comparing cryptographic hashes. It simulates a real SOC use case where analysts track file integrity to detect tampering, malware persistence, or unauthorized modifications.

This is close to host-based intrusion detection (HIDS) 

⸻

##Features

* Generates SHA-256 hashes for files
* Stores baseline hashes
* Detects file modifications, deletions, and new files
* Works on any directory
* Lightweight and fast


## Implementation

import os
import hashlib
import json

BASELINE_FILE = "baseline.json"

def calculate_hash(file_path):
    hasher = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(4096):
                hasher.update(chunk)
        return hasher.hexdigest()
    except:
        return None

def generate_baseline(directory):
    baseline = {}

    for root, _, files in os.walk(directory):
        for name in files:
            path = os.path.join(root, name)
            file_hash = calculate_hash(path)
            if file_hash:
                baseline[path] = file_hash

    with open(BASELINE_FILE, "w") as f:
        json.dump(baseline, f, indent=4)

    print("Baseline created.")

def check_integrity(directory):
    if not os.path.exists(BASELINE_FILE):
        print("Baseline not found. Generate it first.")
        return

    with open(BASELINE_FILE, "r") as f:
        baseline = json.load(f)

    current_state = {}

    for root, _, files in os.walk(directory):
        for name in files:
            path = os.path.join(root, name)
            file_hash = calculate_hash(path)
            if file_hash:
                current_state[path] = file_hash

    print("\n=== Integrity Check ===\n")

    # Check modified and deleted files
    for path, old_hash in baseline.items():
        if path not in current_state:
            print(f"[DELETED] {path}")
        elif current_state[path] != old_hash:
            print(f"[MODIFIED] {path}")

    # Check new files
    for path in current_state:
        if path not in baseline:
            print(f"[NEW FILE] {path}")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="File Integrity Monitor")
    parser.add_argument("mode", choices=["baseline", "check"])
    parser.add_argument("directory", help="Directory to monitor")

    args = parser.parse_args()

    if args.mode == "baseline":
        generate_baseline(args.directory)
    elif args.mode == "check":
        check_integrity(args.directory)
