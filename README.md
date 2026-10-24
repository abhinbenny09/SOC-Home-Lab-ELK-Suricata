# 🛡️ SOC Home Lab: ELK Stack & Suricata Network Security Monitoring

A complete **Security Operations Center (SOC) Home Lab** designed for real-time network traffic analysis, threat detection, and automated threat intelligence enrichment using **Suricata IDS**, the **ELK Stack (Elasticsearch, Logstash, Kibana)**, and custom **Python scripts**.

---

## 📌 Project Overview

This project demonstrates a fully functional Network Security Monitoring (NSM) and automated threat enrichment pipeline designed to:

- **Detect** malicious network traffic using Suricata IDS.
- **Ingest and structure** complex log streams via Filebeat and Logstash.
- **Index, store, and correlate** security event data in Elasticsearch.
- **Visualize** real-time attack metrics and alerts on custom Kibana Dashboards.
- **Automatically query** threat feeds (VirusTotal / AlienVault OTX) using custom Python scripts (`enrichment.py`) to categorize suspicious indicators.
- **Trigger** instant security notifications (`notify.py`) for high-severity detections.

---

## 🛠️ Technologies Used

- **IDS / NTA**: Suricata IDS
- **SIEM & Log Management**: Elasticsearch, Logstash, Kibana (ELK Stack), Filebeat
- **Automation & Scripting**: Python 3 (`enrichment.py`, `notify.py`)
- **Containerization**: Docker, Docker Compose
- **Threat Intelligence**: VirusTotal API, AlienVault OTX
- **Reconnaissance & Testing**: Nmap

---

## 🏗️ Architecture

```text
       Network Traffic / Attack Simulation
                        │
                        ▼
                   Suricata IDS
                        │
                        ▼
            Filebeat / Logstash Pipeline
                        │
       ┌────────────────┴────────────────┐
       ▼                                 ▼
Elasticsearch                     Python Enrichment Engine
       │                        (VirusTotal & AlienVault OTX)
       ▼                                 │
Kibana Dashboards                        ▼
                               Notification Engine
 ```

## ⚔️ Attack Simulations

The following network attack vectors were simulated against the monitored network interface to test the responsiveness of Suricata rules and the ELK logging pipeline:

Nmap SYN Scan: Stealth port scanning to map open ports across active subnets.

Service Version Detection (-sV): Scanning application footprints to detect service banners and vulnerabilities.

OS Fingerprinting (-O): Probing TCP/IP stack behavior to identify target operating systems.

ICMP Ping Flood: Generating high-density ICMP echo requests to test volumetric threshold alerts.

Payload / Malformed Packet Injection: Injecting malicious signatures to verify custom Suricata IDS rule alerts.

Threat Intelligence Pipeline Test: Injecting mock JSON alerts (test_event.json) to trigger automatic enrichment scripts.

## 📷 Screenshots

<img width="1901" height="840" alt="Screenshot 2026-09-29 102818" src="https://github.com/user-attachments/assets/db6fa01d-e6e8-4644-bfa1-b41bbb38b536" />

<img width="1340" height="905" alt="Screenshot 2026-10-08 122601" src="https://github.com/user-attachments/assets/ba12883c-2232-46fe-8f1e-993acc6c6782" />

<img width="1896" height="962" alt="Screenshot 2026-10-08 121918" src="https://github.com/user-attachments/assets/9f9dc877-3f23-4185-9e53-4363b646b576" />

## 🎯 Outcomes

Successfully built an automated, end-to-end SOC Home Lab capable of capturing raw network traffic, identifying malicious activity using Suricata IDS, enriching suspicious IOCs via external threat intelligence APIs, and displaying real-time security insights inside Kibana.
