


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
- timestamp {Done}
- protocol_type 
- srcIP {Done}
- DestIP {Done}
- payloadSize {Done}

### Data_Link_Layer
(Layer 2)
- PacketID
- srcMAC {Done}
- destMAC {Done}
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
- srcIP
- destIP
- Protocol

#### IPv4_Header
(Layer 3)
- packet_id
- ttl
- checksum
- FragmentOffset
- Options

#### IPv6_Header
(Layer 3)
- packetID
- flow_label
- hop_limit
- ExtensionHeaders

### Transport_Layer
(Layer 2)
- PacketID
- srcPort
- destPort

#### TCP_Header
(Layer 3)
- PacketID
- SequenceNum
- AckNum
- Flags
- WindowsSize

#### UDP_Header
(Layer 3)
- PacketID
- Length
- Checksum

#### ICMP_Header
(UNEVALUATED)
(Layer 3)
- PacketID
- type
- code

### Application_Layer
(Layer 2)
- PacketID
- App_Protocol

#### HTTP_Header
(Layer 3)
- PacketID
- http_method
- host
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

