# botsv2-incident-response
Conducted a targeted threat hunting investigation utilizing Splunk Enterprise on the BOTSv2 dataset. Successfully identified a multi-stage corporate compromise involving an insider threat (data exfiltration) and an external Advanced Persistent Threat (APT) group utilizing state-sponsored tools.
Phase 1: The Insider Threat (Amber Turing)
Objective: Investigate suspicious employee activity.

Evidence Uncovered: Targeted reconnaissance against a competitor (www.berkbeer.com) and exfiltration of corporate leadership data via an image asset (/images/ceoberk.png).

The SPL: Include your exact index=botsv2 sourcetype="stream:http" src_ip="10.0.2.101" query to prove your work.
Phase 2: External Reconnaissance & Perimeter Attack
Objective: Identify malicious scanning on the public web server (www.froth.ly).

Evidence Uncovered: A spoofed/exotic User-Agent string revealing a state-backed signature (NaenaraBrowser/3.5b4) originating from a masked ExpressVPN node (85.203.47.86), actively targeting the internal corporate web server (172.31.6.251).

The SPL: Paste your stats count by http_user_agent | sort + count logic.
