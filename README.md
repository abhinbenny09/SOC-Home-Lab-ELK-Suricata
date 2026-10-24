🛡️ SOC Home Lab: ELK Stack & Suricata Network Security Monitoring
A complete Security Operations Center (SOC) Home Lab designed for real-time network traffic analysis, threat detection, and automated threat intelligence enrichment using Suricata IDS, the ELK Stack (Elasticsearch, Logstash, Kibana), and custom Python scripts.

📌 Project Overview
This project demonstrates a fully functional Network Security Monitoring (NSM) and automated threat enrichment pipeline designed to:
. Detect malicious network traffic using Suricata IDS.

. Ingest and structure complex log streams via Filebeat and Logstash.

. Index, store, and correlate security event data in Elasticsearch.

. Visualize real-time attack metrics and alerts on custom Kibana Dashboards.

. Automatically query threat feeds (VirusTotal / AlienVault OTX) using custom Python scripts (enrichment.py) to categorize suspicious indicators.

. Trigger instant security notifications (notify.py) for high-severity detections.

🛠️ Technologies Used
. IDS / NTA: Suricata IDS

. SIEM & Log Management: Elasticsearch, Logstash, Kibana (ELK Stack), Filebeat

. Automation & Scripting: Python 3 (enrichment.py, notify.py)

. Containerization: Docker, Docker Compose

. Threat Intelligence: VirusTotal API, AlienVault OTX

. Reconnaissance & Testing: Nmap

🏗️ Architecture
Plaintext
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
                               
 ⚔️ Attack Simulations & Testing
The system was validated by executing simulated network attacks and analyzing the resulting IDS rules and Logstash pipelines:

Nmap Port Scans: TCP SYN Scan, Service Version Detection (-sV), and OS Fingerprinting (-O).

ICMP Ping Floods: Network sweep and volumetric traffic testing.

Malformed Packet / Payload Injection: Verified custom Suricata detection rules.

Threat Intelligence Pipeline Validation: Injected mock JSON payloads (test_event.json) to confirm automatic IP/Hash enrichment and alert dispatch.

🚀 Features
Real-Time Threat Detection: Continuous packet inspection powered by custom and open-source Suricata rulesets.

Automated Threat Intelligence: Custom enrichment.py script automatically pulls reputation scores from VirusTotal and OTX.

Centralized Log Normalization: Logstash pipelines map incoming JSON log streams into normalized Elasticsearch documents.

Automated Security Notifications: Lightweight notify.py module fires instant alerts when critical threat thresholds are breached.

Reproducible Infrastructure: Full stack orchestrated via docker-compose.yml for isolated deployment.

📂 Repository Structure

.
├── docker-compose.yml       # Orchestrates Elasticsearch, Kibana, and Logstash services
├── Dockerfile-logstash      # Custom container build for Logstash
├── Logstash/                # Pipeline definitions & configuration
│   ├── config/logstash.yml
│   └── pipeline/logstash.conf
├── filebeat-ti/             # Filebeat threat intelligence module configs
│   └── filebeat.yml
├── enrichment.py            # Python script for querying threat intelligence APIs
├── notify.py                # Python script for security alert notifications
├── kibana.yml               # Kibana configuration file
├── test.json                # Test event payload for pipeline verification
└── test_event.json          # Mock Suricata alert data for testing enrichment

📷 Screenshots

![alt text](<Screenshot 2026-09-29 102818.png>)




🎯 Outcome
Successfully built an automated, end-to-end SOC Home Lab capable of capturing raw network traffic, identifying malicious activity using Suricata IDS, enriching suspicious IOCs via external threat intelligence APIs, and displaying real-time security insights inside Kibana.