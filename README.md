<<<<<<< HEAD
# 🚀 Network Security Monitoring System 🔒

This project is a comprehensive network security monitoring system that captures, parses, categorizes, and analyzes network traffic in real time. It uses an AI model for anomaly detection and helps identify threats such as DDoS attacks, brute force attempts, malware payloads, and data exfiltration.

---

## 📑 Table of Contents

- [File Structure](#file-structure)
- [Processing Flow](#processing-flow)
- [Database Schema & Packet Metadata](#database-schema--packet-metadata)
- [Network Protocol Layers](#network-protocol-layers)
- [Security Attacks](#security-attacks)
- [Conclusion](#conclusion)

---

## 📂 File Structure

src/ ├── main/ │ ├── java/com/network/security/ │ │ ├── controller/ │ │ ├── service/ │ │ ├── repository/ │ │ ├── model/ │ │ ├── util/ │ │ └── security/ │ ├── resources/ │ │ ├── application.properties │ │ ├── log4j2.xml │ │ └── schema.sql └── test/java/com/network/security/ ├── service/UserServiceTest.java └── service/NetworkMonitorTest.java

---

## 🔄 Processing Flow

- **🏁 Start**
- **📡 Packet Capture**
  - Capture network packets in real time.
  - Extract network packet details.
  - Store raw packets in a temporary buffer (initial storage).
- **🔍 Packet Parsing & Metadata Extraction**
  - Extract important fields such as headers, payloads, timestamps, and ports.
- **🗂️ Traffic Categorisation**
  - Classify packets based on protocols (TCP, UDP, HTTP, etc).
- **🤖 Anomaly Detection (AI Model)**
  - Analyze packet behavior against historical trends.
  - Identify anomalies such as:
    - **DDoS Attack:** Abnormal traffic spikes.
    - **Brute Force Attack:** Multiple failed logins.
    - **Malware Payload:** Suspicious file hashes or IPs.
    - **Data Exfiltration:** Large outbound transfers.
- **💾 Store Packets in MySQL Database**
  - Save metadata, anomalies, and flagged packets.
  - Keep logs for forensic analysis.
- **🚨 Real-Time Alert Generation**
  - If an anomaly is detected, raise an alert and notify the admin.
- **📊 Network Traffic Visualization**
  - Display line charts, alert panels, and tables.
- **👨‍💻 User Action**
  - Admin/User reviews the traffic and takes necessary security actions (e.g., block IP, adjust firewall rules).
- **📝 Report Generation & Exporting**
  - Generate PDF/CSV reports on detected anomalies.
  - Store reports for compliance and audit.

--- 

## ⚠️ Security Attacks

### ARP Attacks
- **Unexpected ARP Replies:** May indicate spoofing.
- **Frequent MAC-IP Changes:** Possible malicious activity.
- **Unusual Protocol Values:** Abnormal values may suggest an attack.

#### ARP Spoofing
- **Indicators:**  
  - `src_mac`  
  - `src_IP`  
  - `OPER`

#### ARP Cache Poisoning
- **Indicators:**  
  - `src_ip`  
  - `dest_ip`  
  - `dest_mac`

#### ARP DoS
- **Indicators:**  
  - `HTYPE`  
  - `PTYPE`  
  - `HLEN`  
  - `PLEN`  
  - `src_mac`  
  - `OPER`

#### Gratuitous ARP Spoofing
- **Indicators:**  
  - `src_ip`  
  - `dest_ip`  
  - `src_mac`
 
=======

 


# Database

## Packet-Data Database
## Rule_Violation Database

>>>>>>> 808a343 (Updated packet handling services and removed IpV4Headers.md)

# Rule-Based Intrusion and Anomally Detection System

## Rule-Based IDS
Uses predefined rules to detect malicious traffic.
File: .json

### Blacklist Rules
- blacklisted_ips {lets see}
- blacklisted_ports {lets see}

### Port Scanning Detection
- syn_flood_threshold
- fiin_flood_threshold
- xmas_flood_threshold
- null_flood_threshold
- icmp_flood_threshold
- port_flood_threshold

### Protocol Violation Rules
- restricted_protocols
- non_standard_ports
- block_external_icmp
- detect_malformed_packets
- invalid_tcp_flags
- packet_size_limits

### Dos/ DDoS Attack
- syn_flood_threshold
- icmp_flood_threshold
- udp_flood_threshold
- http_flood_threshold
- slowloris_threshold

### Packet Ispection Rules
- dpi_keywords
- payload_length_threshold
- encrypted_traffic_check

### Brute-Force Attack Detection
- ssh_brute_force_threshold
- ftp_brute_force_threshold
- http_auth_brute_force_threshold
- email_brute_force_threshold

### Insider Threat Detection
- lateral_movement_threshold
- data_exfil_threshold
- privilege_escalation_detection

### DNS & Web Filtering
- blacklisted_domains
- dns_tunneling_threshold
- typosquatting_detection
- suspicious_user_agents


### Logging & Alerting Config
- log_level
- alert_methods  {["email", "syslog"]}
- log_retention_days
- adaptive_thresholding

## Anomaly Detection
Compares traffic patterns to a baseline of normal activity.

### Monitoring
- Traffic Baseline Monitoring
- Threshhold Based Detection
- Machine Learning 


### Maintain Packet Statistics

- Total Packets per sec
- TCP SYN packets per second
- ICMP packets per second


<<<<<<< HEAD

# AI - Based Intrusion and Anomally Detection

## Structured Data 
- Randon Forest
- XGBoost
- Support Vector Machines
- Isolation Forest

## For Sequential Data
- RNN
- LSTM
- Autoencoders
- Transformer Models

## Reinforcement Learning
- PPO


# Alert & Response System

- Logging it in database
- Sending an alert to admin {email, syslog}
- Take Action {Block IP, Update Firewall}

# Visualization

## Real Time Network Traffic Monitoring

- Line graph
- Number of packets processed 


## Suspicios Activity

- Donut Chart
- Categories of detected threats {Port Snanning, DDoS Attack, Malformed Packets}

## Toop Malicious IP

- Bar Chart
- IPs that triggered most rules/anomalies.
- Identifies recurring threats or botnets

## AI Based Anomaly Detection over Time

- Scatter Plot
- Ai anoaly score per packets/session
- Detect Suspicious clusters of traffic
{x-axis: timestamp
y-axis: Anomaly score}

## Geolocation Mpa of Attack Sources

- World Map
- Locations of Malicious IPs
- Locations of high traffic pin points

## Port Activity Analysis

- Stacked Bar Chart
- Number of Connection attempts per port
{Identify suspicious access attempts on certain ports}

## Attack Trends Over Time {Time Series Analysis}

- Time-Series Line Chrt
- Number of Attacks detected per minute/hour/day
{
    x-axis: every hour
    y-axis: total detected intrusion
    Trendlines: Attack surges
}

## Top 10 Most Attacked Services & Protocols

- Stacked Bar Chart
- Number of attacks on different services {HTTP, SSH, FTP}

## Protocol-Based Anomaly Detection

- Bubble Chart
- Anomaly Score for each protocol detected

## Failed vs Succcessful intrusion attempts

- Cuage Chart
- Count of total attacks attempts vs successfull intrusion

## Correlation btw Attacks & Traffic Spikes

- Dual-Axis Line chrt
- Total network traffic vs detected atatcks

# PDF Reports

## Components in PDF
- Sumaary of intrusion in past & days / 1 Month
- Most frequent Attack Vector
- List of Blacklisted IPs
- AI based Anomaly score analysis
- Geolocation of attackers
- Port Scanning attempts

{Apache PDFBox}


# Implementing Zero-Copy, Memory-Mapped Buffers, and Ring Buffers in Java NIDS



=======
<<<<<<< HEAD
>>>>>>> 7f32f23 (Updated packet handling services and removed IpV4Headers.md)
---

## 🤝 Conclusion

This README provides an in-depth overview of the system's file structure, processing flow, database schema, detailed network protocol headers, and potential security attacks. It serves as a reference guide for developers and security analysts to understand the project architecture and functionality.

*Happy Securing! 🔒*
=======

# AI - Based Intrusion and Anomally Detection

## Structured Data 
- Randon Forest
- XGBoost
- Support Vector Machines
- Isolation Forest

## For Sequential Data
- RNN
- LSTM
- Autoencoders
- Transformer Models

## Reinforcement Learning
- PPO


# Alert & Response System

- Logging it in database
- Sending an alert to admin {email, syslog}
- Take Action {Block IP, Update Firewall}

# Visualization

## Real Time Network Traffic Monitoring

- Line graph
- Number of packets processed 


## Suspicios Activity

- Donut Chart
- Categories of detected threats {Port Snanning, DDoS Attack, Malformed Packets}

## Toop Malicious IP

- Bar Chart
- IPs that triggered most rules/anomalies.
- Identifies recurring threats or botnets

## AI Based Anomaly Detection over Time

- Scatter Plot
- Ai anoaly score per packets/session
- Detect Suspicious clusters of traffic
{x-axis: timestamp
y-axis: Anomaly score}

## Geolocation Mpa of Attack Sources

- World Map
- Locations of Malicious IPs
- Locations of high traffic pin points

## Port Activity Analysis

- Stacked Bar Chart
- Number of Connection attempts per port
{Identify suspicious access attempts on certain ports}

## Attack Trends Over Time {Time Series Analysis}

- Time-Series Line Chrt
- Number of Attacks detected per minute/hour/day
{
    x-axis: every hour
    y-axis: total detected intrusion
    Trendlines: Attack surges
}

## Top 10 Most Attacked Services & Protocols

- Stacked Bar Chart
- Number of attacks on different services {HTTP, SSH, FTP}

## Protocol-Based Anomaly Detection

- Bubble Chart
- Anomaly Score for each protocol detected

## Failed vs Succcessful intrusion attempts

- Cuage Chart
- Count of total attacks attempts vs successfull intrusion

## Correlation btw Attacks & Traffic Spikes

- Dual-Axis Line chrt
- Total network traffic vs detected atatcks

# PDF Reports

## Components in PDF
- Sumaary of intrusion in past & days / 1 Month
- Most frequent Attack Vector
- List of Blacklisted IPs
- AI based Anomaly score analysis
- Geolocation of attackers
- Port Scanning attempts

{Apache PDFBox}
>>>>>>> 808a343 (Updated packet handling services and removed IpV4Headers.md)
