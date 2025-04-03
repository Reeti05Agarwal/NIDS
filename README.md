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

## 🗄️ Database Schema & Packet Metadata

### 📌 Packet_Metadata (Parent Table - Layer 1)
- **PacketID**
- **timestamp** (captured time) ✅
- **protocol_type**
- **payloadSize** ✅

### 🔗 Data_Link_Layer (Layer 2)
- **PacketID**
- **srcMAC** ✅
- **destMAC** ✅
- **protocolType**

#### ➡️ Ethernet_Header (Layer 3)
- **PacketID**
- **FrameCheckSeq**
- **EtherType**

#### ➡️ Wi-Fi_Header (Layer 3)
- **PacketID**
- **bssid**
- **seqControl**
- **frameControl**

### 🌐 Network_Layer (Layer 2)
- **PacketID**
- **srcIP**
- **destIP**
- **Protocol**

#### ➡️ IPv4_Header (Layer 3)
- **packet_id**
- **ttl**
- **checksum**
- **FragmentOffset**
- **Options**

#### ➡️ IPv6_Header (Layer 3)
- **packetID**
- **flow_label**
- **hop_limit**
- **ExtensionHeaders**

### 🔀 Transport_Layer (Layer 2)
- **PacketID**
- **srcPort**
- **destPort**

#### ➡️ TCP_Header (Layer 3)
- **PacketID**
- **SequenceNum**
- **AckNum**
- **Flags**
- **WindowsSize**

#### ➡️ UDP_Header (Layer 3)
- **PacketID**
- **Length**
- **Checksum**

#### ➡️ ICMP_Header (Layer 3) *(UNEVALUATED)*
- **PacketID**
- **type**
- **code**

### 📡 Application_Layer (Layer 2)
- **PacketID**
- **App_Protocol**

#### ➡️ HTTP_Header (Layer 3)
- **PacketID**
- **http_method**
- **host**
- **user_agent**
- **Auth**
- **COntentType**

#### ➡️ DNS_Header (Layer 3)
- **packetID**
- **query_type**
- **reponse_code**
- **TransactionID**
- **Flags**
- **Question**

#### ➡️ TLS_Header (Layer 3)
- **packetID**
- **tls_version**
- **handshake_type**
- **ContentType**
- **Headers**

---

## 🌐 Network Protocol Layers

### 🔌 Data Link Layer
- **Ethernet Header (Wired Network):**
  - Preamble, Start Frame Delimiter, Destination MAC Address, Source MAC Address, EtherType, Payload, Frame Check Sequence.
- **Wi-Fi Header (Wireless Network):**
  - Frame Control, Duration ID, Destination MAC Address, Source MAC Address, BSSID, Sequence Control, Frame Body, FCS.

### 🌍 Network Layer Headers

#### IPv4 Header:
- **Version:** 4 bits
- **Header Length:** 4 bits
- **Differentiated Services:** 6 bits
- **ECN:** 2 bits
- **Total Length:** 2 bytes
- **Identification:** 2 bytes
- **Flags:** 3 bits (Reserved, Don't Fragment, More Fragments)
- **Fragment Offset:** 13 bits
- **Time to Live:** 1 byte
- **Protocol:** 1 byte (TCP: 6, UDP: 17, ICMP: 1)
- **Header Checksum:** 2 bytes
- **Source IP Address:** 4 bytes
- **Destination IP Address:** 4 bytes
- **Options:** 0-40 bytes (optional: security, routing, timestamping)
- **Padding:** Ensures header is a multiple of 32 bits

#### IPv6 Header:
- **Version:** 4 bits
- **Traffic Class:** 8 bits
- **Flow Label:** 20 bits
- **Payload Length:** 2 bytes
- **Next Header:** 1 byte
- **Hop Limit:** 1 byte
- **Source IPv6 Address:** 16 bytes
- **Destination IPv6 Address:** 16 bytes
- **Extension Headers:** Optional (e.g., routing, fragmentation, authentication)

### 🔀 Transport Layer Headers

#### TCP Header:
- **Source Port:** 2 bytes
- **Destination Port:** 2 bytes
- **Sequence Number:** 4 bytes
- **Acknowledgment Number:** 4 bytes
- **Data Offset:** 4 bits
- **Reserved:** 3 bits
- **Flags:** 9 bits (NS, CWR, ECE, URG, ACK, PSH, RST, SYN, FIN)
- **Window Size**
- **Checksum**
- **Urgent Pointer**
- **Options:** 0-40 bytes (for TCP extensions)

#### UDP Header:
- **Source Port:** 2 bytes
- **Destination Port:** 2 bytes
- **Length:** 2 bytes
- **Checksum:** 2 bytes

### 📡 Application Layer Headers

#### HTTP/HTTPS Headers:
- **Request Line:** HTTP Method (GET, POST), URL, HTTP Version
- **Headers:** Host, User-Agent, Content-Type, Content-Length, Auth

#### DNS Header:
- **Transaction ID:** 2 bytes
- **Flags:** 2 bytes
- **Questions:** 2 bytes
- **Answer RRs:** 2 bytes
- **Authority RRs:** 2 bytes
- **Additional RRs:** 2 bytes

#### TLS/SSL Header:
- **Content Type:** 1 byte
- **Version:** 2 bytes
- **Length:** 2 bytes
- **Handshake Protocol:** Variable length

### ⚙️ Ether Type Values (Examples)
- `0x0800` – IPv4
- `0x0806` – ARP (Address Resolution Protocol)
- `0x86DD` – IPv6
- `0x8100` – IEEE 802.1Q VLAN Tagging
- `0x8847` – MPLS Unicast
- `0x8848` – MPLS Multicast
- `0x8863` – PPPoE Discovery Stage
- `0x8864` – PPPoE Session Stage
- `0x888E` – EAP over LAN (IEEE 802.1X Authentication)
- `0x88A2` – ATA over Ethernet (AoE)
- `0x88CC` – LLDP (Link Layer Discovery Protocol)
- `0x8902` – IEEE 802.1AE (MACsec)
- `0x9000` – Ethernet Configuration Testing Protocol (Loopback)

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



# File Structure


src/
 ├── main/
 │   ├── java/com/network/security/
 │   │   ├── controller/
 │   │   ├── service/
 │   │   ├── repository/
 │   │   ├── model/
 │   │   ├── util/
 │   │   ├── security/
 │   ├── resources/
 │   │   ├── application.properties
 │   │   ├── log4j2.xml
 │   │   ├── schema.sql
 ├── test/java/com/network/security/
 │   ├── service/UserServiceTest.java
 │   ├── service/NetworkMonitorTest.java




# Flowchart

1. Start

2. Packet Capture
    - Capture network packets in real time
    - Extract network packet Details

3. Store Raw Packets in temp buffer
    - Save unprocessed packets for initial storage

4. Packet parsing and metadata extrc=action
    - Extract imp fields (headers, payload timesteps, ports)

5. Traffic Categorisation
    - Classify the packets based on protocols (TCP, UDP, HTTP, etc)

6. Anomaly Detection (AI Model)
    - Analyse packet behaviour and comapre with historical trends
    - Identify anomalies
        - DDoS Attack (abnormal traffic spikes)
        - Brute Force Attack (Mutiple Failed Logins)
        - Malware Payload  (Suspicious File Hashes/IPs)
        - Data Exfiltration (Large Outbound Transfers)

7. Store Packets in MYSQL Database
    - Store metadat, anomalies, and flagged packets
    - Save logs for forensic analysis

8. Real-Time Alert Generation
    - If anomaly Detected -> Raise an Alert
    - Notify Admin

9. Network Traffic Visualisation
    - Line Chrts
    - Alert Panel
    - Tables

10. User Action
    - Admin/User reviews traffic
    - Takes necessary security actions (Block Ip, Adjust Firewal Rules)

11. Report Generation and Exporting 
    - Generate PDF/CSV reports on detected anomalies
    - Store reports for compliance and audit



# Database

Packet_Metadata
│
├── Data_Link_Layer
│   ├── Ethernet_Header
│   ├── Wi-Fi_Header
│
├── Network_Layer
│   ├── IPv4_Header
│   ├── IPv6_Header
│
├── Transport_Layer
│   ├── TCP_Header
│   ├── UDP_Header
│   ├── ICMP_Header
│
└── Application_Layer
    ├── HTTP_Header
    ├── DNS_Header
    ├── TLS_Header


## Packet Metadata
(Parent Table)
(Layer 1)
- PacketID 
- timestamp  
- protocol_type  
- payloadSize 

### Data_Link_Layer
(Layer 2)
- PacketID
- SRC_MAC  
- DEST_MAC  
- protocolType

#### Ethernet_Header
(Layer 3)
- PacketID
- FrameCheckSeq
- EtherType

#### Wifi_Header
(Layer 3)
- PacketID
- bssid
- seqControl
- frameControl

### Network_Layer
(Layer 2)
- PacketID
- SRC_IP
- DEST_IP

#### IPv4_Header
(Layer 3)
- packet_id
- TTL
- CHECKSUM
- FragmentOffset
- PROTOCOL {ICMP, TCP, UDP}

#### IPv6_Header
(Layer 3)
- packetID
- SRC_IP
- DEST_IP
- TRAFFIC_CLASS
- FLOW_LABEL
- HOP_LIMIT
- EXTENSION_HEADERS

#### ARP
- HTYPE
- PTYPE
- HLEN
- OPER
- PLEN
- SRC_MAC
- SRC_IP
- DEST_MAC
- DEST_IP
- ARP_OPERATION

#### VLAN

### Transport_Layer
(Layer 2)
- PacketID
- SRC_PORT
- DEST_PORT

#### TCP_Header
(Layer 3)
- PacketID
- SRC_PORT
- DEST_PORT
- SEQUENCE_NUM
- ACK_NUM 
- FLAGS {URG, ACK, PSH, RST, SYN, FIN}
- WINDOWS_SIZE

#### UDP_Header
(Layer 3)
- PacketID
- SRC_PORT
- DEST_PORT
- LENGTH
- CHECKSUM

#### ICMP_Header
(UNEVALUATED)
(Layer 3)
- PacketID
- ICMP_TYPE
- ICMP_CODE
- CHECKSUM
- PACKET_ID
- SEQUENCE_NUM

### Application_Layer
(Layer 2)
REMAINING
- PacketID
- APP_PROTOCOL

#### HTTP_Header
(Layer 3)
- PacketID
- http_method
- HOST {like www.example.com}
- user_agent
- Auth
- COntentType

#### DNS_Header
(Layer 3)
- packetID
- query_type
- reponse_code
- TransactionID
- Flags
- Question

#### TLS_Header
(Layer 3)
- packetID
- tls_version
- handshake_type
- ContentType


## Rule_Violation
(packets that violated predefined rules (ip_blacklisting, protocol_violation, etc))
- violationID
- PacketID
- Rule_name
- Description {details of rule violation}
- Severity {Low, Medium, High, Critical}
- Timestamp {Time of violation detected}

## Blacklisted_IPs
- ip_address
- threat_type {type of attack: DDoS, Malware}
- Detected_by {Source: manual, AI, rule-based}
- First_Seen {First Detection Timestamp}
- Last_Seen {Last Detection Timestamp}
- Confidence {probability of being malicious}

## Anomalous_Packets
(Stores packets classified as anomalies by AI Model)
- Anomaly_ID
- Packet_ID
- Detected_By {Model used for detecting}
- Anomaly_Score {Probability of being anomaly}
- Predicted_Class {Malicious/Normal}
- Reason {Featres that triggered the anomaly}
- Timestamp

## Attack_Signatures
(Stores AI-identified attack patterns)
- Signature_ID
- Attack_Type {SQL Injection}
- Features {Key network Features contributing}
- Confidence_Score {AI probability}
- Last_Seen {Last Detection Timestamp}

## Security_Alert
(Stores alerts generated when packet is classified as malicious)
- Alert_ID
- Packet_ID
- Detection_Method
- Severity
- Message
- Action_Taken
- Timestamp

## Incident_Responses
(Logs actions taken after an intrusion)
- Response_ID
- Alert_ID
- Action
- Status
- Responder
- Timestamp

## Model_Performance
(Tracks AI Model accuracy and learning behaviour)
- Log_ID 
- Model_Name
- Accuracy
- Precision
Recall
- Last_Trained

## False_Detection
(helps Fine-Tune AI Model)
- Log_ID
- Packet_ID
- Actual_Class {True label: Normal/Malcious}
- Predicted_Class 
- Reason

# Headers

## Data Link Layer

### Ethernet Header (Wired Network)

- Preamble
- Start Frame Delimiter
- Dest MAC Add
- Src MaC Add
- EtherType
- Payload
- Frame Check Sequence

### Wifi Header (Wireless Network)

- Frame Control
- Duration ID
- Dest MAC Add
- Src MAC Add
- BSSID
- Sequence Control
- Frame Body 
- FCS


## Network Layer Headers

### IPv4 Header

- Version (4 bits)
- Header Length (4 bits)
- Differentiated Services (6 bits)
- ECN (2 bits)
- Total Length (2 bits)
- Identification (2 bits)
- Flags (3 bits) (Reservces bit: 1 bit, dont fragment: 1 bit, more fragment: 1 bit)
- Fragment Offset (13 bits)
- Time to live (1 bytes)
- Protocol (1 byte) (TCP: 6, UDP: 17, ICMP:1)
- Header Checksum (2 bytes)
- Src IP Add (4 bytes)
- Dest IP Address (4 bytes)
- Options (optional: security, routing, timestamping) (0-40 bytes)
- Padding (ensures the header is a multiple of 32 bits) (32 bits)

### IPv6

- version (4 bits)
- Traffic class (8 bits)
- Flow Label (20 bits)
- Payload Length (2 bytes)
- Next Header (1 byte)
- Hop Limit (1 bytes)
- Src IPv6 Add (16 bytes)
- Dest IPv6 Add (16 bytes)
- Extension Headers (optional: Routing, fragmentation, auth)

## Transport Layer Headers

### TCP Header (20 - 60 bytes)

- Src IP Add (2 bytes)
- Dest IP Address (2 bytes)
- Sequence number (4 bytes)
- Ack Number (4 bytes)
- Data Offset (4 bits)
- Resersed (3 bits)
- flags (9 bits) (NS, CWR, ECE, URG, ACK, PSH, RST, SYN, FIN)
- WIndows Size
- Checksum
- Urgent Pointer
- Options (0-40 bytes) for tcp extensions


### UDP Header

- Src Port (2 bytes)
- Dest Port (2 bytes)
- Length (2 bytes)
- Checksum (2 bytes)

## Application Layer Headers

### HTTP/HTTPS Headers

- Request Line : HTTP Method (GET, POST), URL, HTTP Version
- Headers 
    - Host
    - User-Agent
    - COntent-Type
    - COntent-Length
    - Auth

### DNS Header

- Transaction ID (2 bytes)
- Flags (2 bytes)
- Questions (2 bytes)
- Answer RRs (2 bytes)
- Authority RRs (2 bytes)
- Additional RRs (2 bytes)

### TLS/SSL Header

- Content Type (1 byte)
- Version (2 byte)
- Length (2 byte)
- Handshake Protocol (variable length)



# Ether Type

EtherType (Hex)	Protocol
0x0800	IPv4
0x0806	ARP (Address Resolution Protocol)
0x86DD	IPv6
0x8100	IEEE 802.1Q VLAN Tagging
0x8847	MPLS Unicast
0x8848	MPLS Multicast
0x8863	PPPoE Discovery Stage
0x8864	PPPoE Session Stage
0x888E	EAP over LAN (IEEE 802.1X Authentication)
0x88A2	ATA over Ethernet (AoE)
0x88CC	LLDP (Link Layer Discovery Protocol)
0x8902	IEEE 802.1AE (MACsec)
0x9000	Ethernet Configuration Testing Protocol (Loopback)


# Attacks

## ARP:

(Unexpected ARP replies, Frequest MAC-IP changes, Unusual Protocol values)
1. ARP Spoofing
    - src_mac
    - src_IP
    - OPER

2. ARP Cache Poisoning
    - src_ip
    - dest_ip
    - dest_mac

3. ARP DoS
    - HTYPE
    - PTYPE
    - HLEN
    - PLEN
    - src_mac
    - OPER

4. Gratuitous ARP Spoofing
    - src_ip
    - dest_ip
    - src_mac

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
