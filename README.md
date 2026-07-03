# Python Security Tools

## Overview

This repository contains a collection of Python-based tools developed to simulate Security Operations Center (SOC) workflows during hands-on training. The tools were written as part of a structured learning process while working through labs on the LetsDefend platform.

These implementations focus on practical detection, analysis, and investigation techniques commonly used in real-world security operations.

---

## Context

These are the tools I used for simulating SOC operations as I was learning to add to my skills using the LetsDefend platform labs. Since everything was conducted in a controlled LetsDefend lab environment, I implemented these scripts to better understand how underlying detection and analysis mechanisms work beyond GUI-based tools.

The goal was not just to use security tools, but to understand and replicate their logic at a lower level.

---

## Tools Included

### 1. Memory String Analyzer

Extracts and analyzes printable strings from binary files or memory dumps to identify:

* Suspicious command execution patterns
* Embedded URLs
* Encoded payloads (Base64)
* Indicators of potential code execution

### 2. IOC Extractor

Parses input data to extract Indicators of Compromise such as:

* IP addresses
* Domains
* File hashes

### 3. Suspicious URL Analyzer

Identifies potentially malicious URLs based on:

* Structural anomalies
* Keyword patterns
* Encoding indicators

### 4. Log Analyzer

Processes log files to detect:

* Errors and anomalies
* Suspicious activity patterns
* Failed authentication attempts

### 5. Login Page Detection Tool

Analyzes content to identify potential phishing or fake login pages based on keyword and structure patterns.

### 6. Threat Lookup Utility

Performs basic correlation and lookup logic to simulate threat intelligence enrichment.

---

## Key Takeaways

Working on these tools helped reinforce several important concepts:

* How detection logic is implemented at a programmatic level
* The structure and behavior of common attack artifacts
* The importance of string analysis in malware investigation
* How SOC tools abstract underlying processes
* The role of automation in triaging and analyzing security data

---

## Design Approach

* Lightweight and modular implementations
* Focus on clarity over complexity
* Heuristic-based detection for learning purposes
* Built using standard Python libraries for portability

---

## Limitations

* These tools are not production-grade
* Detection logic is simplified and may produce false positives
* No integration with external threat intelligence APIs (by design)

---

## Future Improvements

* Integration with threat intelligence platforms
* YARA rule support for pattern-based detection
* Structured output (JSON/CSV) for pipeline integration
* Enhanced parsing for binary formats (e.g., PE analysis)

---

## Usage

Each tool is standalone and can be executed independently. Refer to individual scripts for usage instructions and input requirements.

---

## Final Note

This repository represents a hands-on approach to understanding security operations by building simplified versions of analytical tools used in SOC environments. The focus is on learning through implementation rather than relying solely on existing platforms.
