Packet_Metadata Table:
PacketID → timestamp, protocol_type, srcIP, destIP, payloadSize

PacketID uniquely identifies each packet and determines the timestamp, protocol type, source IP, destination IP, and payload size.

Packet_Data_Link Table:
PacketID → protocolType

PacketID uniquely identifies each packet's data link layer and determines the protocol type.

Packet_MAC Table:
PacketID → srcMAC, destMAC

PacketID uniquely identifies each packet and determines the source and destination MAC addresses.

Ethernet_Header Table:
PacketID → FrameCheckSeq, EtherType

PacketID determines the FrameCheckSeq and EtherType for Ethernet frames.

Wi-Fi_Header Table:
PacketID → bssid, seqControl, frameControl

PacketID determines the Wi-Fi header attributes such as bssid, seqControl, and frameControl.

Network_Layer Table:
PacketID → srcIP, destIP, Protocol

PacketID determines the source IP, destination IP, and protocol in the network layer.

IPv4_Header Table:
packet_id → ttl, checksum, FragmentOffset, Options

packet_id uniquely identifies the IPv4 packet and determines the ttl, checksum, FragmentOffset, and Options fields.

IPv6_Header Table:
packetID → flow_label, hop_limit, ExtensionHeaders

packetID determines the flow_label, hop_limit, and ExtensionHeaders in IPv6 headers.

Transport_Layer Table:
PacketID → srcPort, destPort

PacketID uniquely determines the source and destination ports for the transport layer.

TCP_Header Table:
PacketID → SequenceNum, AckNum, Flags, WindowSize

PacketID determines the SequenceNum, AckNum, Flags, and WindowSize in the TCP header.

UDP_Header Table:
PacketID → Length, Checksum

PacketID uniquely determines the Length and Checksum for UDP headers.

ICMP_Header Table:
PacketID → type, code

PacketID determines the type and code for ICMP headers.

Application_Layer Table:
PacketID → App_Protocol

PacketID uniquely determines the App_Protocol (the application protocol used for that packet).

HTTP_Header Table:
PacketID → http_method, host, user_agent, Auth, ContentType

PacketID determines various HTTP header fields like http_method, host, user_agent, Auth, and ContentType.

DNS_Header Table:
packetID → query_type, response_code, TransactionID, Flags, Question

packetID determines query_type, response_code, TransactionID, Flags, and Question for DNS headers.

TLS_Header Table:
packetID → tls_version, handshake_type, ContentType

packetID determines tls_version, handshake_type, and ContentType in TLS headers.
