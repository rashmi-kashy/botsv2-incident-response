# Project: Enterprise Threat Hunting & Incident Response (Splunk BOTSv2)

## Summary
During a proactive security assessment of the corporate infrastructure for **Froth.ly** (a fictional craft brewery), a multi-stage security compromise was uncovered. This investigation leverages **Splunk Enterprise** to parse, correlate, and analyze millions of raw security logs from the open-source **Boss of the SOC (BOTS) v2** dataset. 

The investigation successfully uncovered and documented two distinct operational threats:
1. **The Insider Threat:** Unauthorized corporate espionage, asset reconnaissance, and data harvesting conducted by an internal employee (`Amber Turing`).
2. **The Perimeter Attack:** An Advanced Persistent Threat (APT) reconnaissance scan targeting public-facing infrastructure, utilizing a nation-state-affiliated browser profile masked via commercial proxy layers.

---

## 🛠️ Environment & Tools
* **SIEM Platform:** Splunk Enterprise (v9.x)
* **Data Source:** Splunk BOTSv2 Dataset
* **Log Types Analyzed:** `stream:http`, `WinEventLog:Security`, Firewalls, and Network Metadata.
* **Core Methodologies:** Indicators of Compromise (IoC) isolation, Long-tail analysis, Data transformation aggregation.

---

##  Investigation Timeline & Findings

### Phase 1: Insider Threat Detection (Amber Turing)
* **Objective:** Audit the network footprint of internal workstation `10.0.2.101` following behavioral anomalies.
* **Findings:** The user bypassed standard internal tools to aggressively scout a direct market competitor (`www.berkbeer.com`). Rather than grabbing standard text assets, the user located and extracted an isolated image asset containing sensitive corporate leadership directories.
* **Key Artifacts Uncovered:**
  * **Host IP:** `10.0.2.101` (Amber Turing)
  * **Target Domain:** `www.berkbeer.com`
  * **Exfiltrated Asset Path:** `/images/ceoberk.png`

### Phase 2: External Reconnaissance & APT Fingerprinting
* **Objective:** Identify anomalous behavior or low-frequency probing hitting the public perimeter (`www.froth.ly`).
* **Findings:** Utilizing long-tail analysis on incoming HTTP web headers, a highly rare, spoofed User-Agent was uncovered. The string explicitly matches the signature of the **Naenara Browser**, an asset tied directly to state-sponsored infrastructure groups out of North Korea (`ko-KP`). 
* **Evasion Tactics Detected:** The threat actor routed commands through a commercial ExpressVPN exit node based in Denmark to mask their physical origin, but failed to sanitize their custom browser signature.
* **Key Artifacts Uncovered:**
  * **Attacker Masked IP:** `85.203.47.86` (Denmark / ExpressVPN)
  * **Target Internal Web Server:** `172.31.6.251`
  * **Attacker Fingerprint:** `Mozilla/5.0 (X11; U; Linux i686; ko-KP; rv: 19.1br) Gecko/20130508 Fedora/1.9.1-2.5.rs3.0 NaenaraBrowser/3.5b4`

---

##  Documented Splunk Queries (SPL)

### 1. Insider Competitor Reconnaissance
Filters noisy background operating system traffic to isolate exact external destination sites visited by the target workstation.
```spl
index=botsv2 sourcetype="stream:http" src_ip="10.0.2.101" 
NOT (site=*.microsoft.com OR site=*.gvt1.com OR site=*msn.com OR site=*.bing.com) 
| stats count by site 
| sort - count
