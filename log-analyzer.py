# simple_log_analyzer.py

A simple Python script that reads log files and identifies basic security-related events such as errors, failed login attempts, and warnings using pattern matching.
It helps demonstrate basic log analysis and threat detection concepts used in cybersecurity.


# Open and read the log file
with open("logs.txt", "r") as file:
    logs = file.readlines()

# Counters
error_count = 0
failed_login_count = 0
warning_count = 0

# Store suspicious lines
suspicious = []

# Loop through each line
for line in logs:
    line = line.strip()  # remove spaces/newlines

    # Pattern matching (simple)
    if "ERROR" in line:
        error_count += 1
        suspicious.append(line)

    elif "Failed login" in line:
        failed_login_count += 1
        suspicious.append(line)

    elif "WARNING" in line:
        warning_count += 1

# Print summary
print("=== LOG ANALYSIS SUMMARY ===\n")

print(f"Errors: {error_count}")
print(f"Failed Logins: {failed_login_count}")
print(f"Warnings: {warning_count}")

print("\n=== Suspicious Events ===\n")

for event in suspicious:
    print(event)
