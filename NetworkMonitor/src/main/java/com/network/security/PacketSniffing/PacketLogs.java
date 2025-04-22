package com.network.security.PacketSniffing;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.sql.Timestamp;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;
import com.network.security.util.PacketUtils;
public class PacketLogs {
private static final Logger LOGGER = Logger.getLogger(PacketLogs.class.getName());
public static void main(String[] args) {
     try {
         // Select Network Interface
         System.out.println("[DEBUG] Fetching available network interfaces...");
         PcapNetworkInterface device = getDevice();
         if (device == null) {
             System.out.println("[ERROR] No network interfaces found.");
             return;
         }

         System.out.println("[INFO] Selected Interface: " + device.getName());
         System.out.println("Selected Interface: " + (device != null ? device.getName() : "None"));
         // Packet Listner
         int snapshotLength = 65536; // in bytes   
         int readTimeout = 50; // in milliseconds 
         final PcapHandle handle;
         handle = device.openLive(snapshotLength, PromiscuousMode.PROMISCUOUS, readTimeout);
         System.out.println("[INFO] Listening for packets...");

         // PacketListener is much more structred than a simple handle.loop
         PacketListener listener = new PacketListener() {
             @Override
             public void gotPacket(Packet packet) {
                System.out.println("==============================Packet received=============================="); 
                System.out.println("[DEBUG] Packet received...");
                 parsePacket(packet.getRawData());
             }
         };

         int maxPackets = 50;
         handle.loop(maxPackets, listener);
         handle.close();
     } catch (Exception e) {
         System.err.println("[ERROR] Exception in main: " + e.getMessage());
         e.printStackTrace();
     }
 }
 static PcapNetworkInterface getDevice() {
     /*
      * Network Interface Function
      * NifSelector().selectNetworkInterface(): Opens a selection prompt for the user
      */
     PcapNetworkInterface device = null;
     try {
         System.out.println("[DEBUG] Selecting network interface...");
         device = new NifSelector().selectNetworkInterface();
     } catch (IOException e) {
         System.err.println("[ERROR] Failed to get network interface: " + e.getMessage());
         e.printStackTrace();
     }
     return device;
 }
 private static Map<String, Object> parsePacket(byte[] packet) {
     Map<String, Object> packetData = new HashMap<>();
     // Ethernet header is 14 bytes
     if (packet == null || packet.length < 14) { 
         LOGGER.log(Level.WARNING, "Packet is null or too short.");
         return packetData;
     }
     ByteBuffer buffer = ByteBuffer.wrap(packet).order(ByteOrder.BIG_ENDIAN);
     // Packet metadata (Layer 1)
     packetData.put("TIMESTAMP", new Timestamp(System.currentTimeMillis()));// TimeStamp
     System.out.println("[DEBUG] Packet received at: " + packetData.get("TIMESTAMP"));
     packetData.put("PACKET_SIZE", packet.length); // Packet size
     System.out.println("[DEBUG] Packet size: " + packetData.get("PACKET_SIZE"));
     packetData.put("PACKET_ID", System.nanoTime()); // Packet ID  )
     System.out.println("[DEBUG] Packet ID: " + packetData.get("PACKET_ID"));
     // Data Link Layer (Layer 2)
     parseEthernetHeader(buffer, packetData);// Ethernet Header
        /*
        Short ethType = (Short) packetData.get("Eth_Type_Short");
        String ethTypeString = (String) packetData.get("ETH_TYPE");
        
        int offset = 0;  
        if (ethType < 0) { // Check for Wi-Fi frame control field
            packetData.put("TYPE", "WIFI");
            parseWiFiHeader(buffer, packetData);
            offset = 24; // Adjust offset for Wi-Fi header length
        } else {
            packetData.put("TYPE", "ETH");
            offset = 14; // Ethernet header length
        }
         */
        int ethType = ((Short) packetData.get("ETH_TYPE")) & 0xFFFF;
        System.out.println("[DEBUG] ETHER TYPE: " + ethType);

        
        int offset = 0;  
        if (packet[0] == 0x08 && packet[1] == 0x00) { // Check for Wi-Fi frame control field
            parseWiFiHeader(buffer, packetData);
            packetData.put("TYPE", "WIFI");
            offset = 24; // Adjust offset for Wi-Fi header length
        } else {
            offset = 14; // Ethernet header length
            packetData.put("TYPE", "ETH");
        }
        System.out.println("[DEBUG] TYPE: " + packetData.get("TYPE"));
        switch (ethType) {
            case 0x0800: parseIPv4(buffer, offset, packetData); break;  // IPv4
            case 0x86DD: parseIPv6(buffer, offset, packetData); break;  // IPv6
            case 0x0806: parseARP(buffer, offset, packetData); break;   // ARP
            default:
                LOGGER.log(Level.INFO, "Unsupported EtherType: {0}", ethType);
                packetData.put("INFO", "Unsupported EtherType: " + ethType);         
        }
        
        return packetData;
 }
 private static void parseEthernetHeader(ByteBuffer buffer, Map<String, Object> packetData) {
     try {
         buffer.position(0);  // Ethernet headers start from beginning if this is a raw frame
         byte[] destMac = new byte[6];
         buffer.get(destMac); 
         packetData.put("DEST_MAC", PacketUtils.bytesToMac(destMac)); // Destination MAC address
         System.out.println("[DEBUG] Destination MAC (Ethernet Header): " +  packetData.get("DEST_MAC"));
         byte[] srcMac = new byte[6];
         buffer.get(srcMac); 
         packetData.put("SRC_MAC", PacketUtils.bytesToMac(srcMac)); // Source MAC address
         System.out.println("[DEBUG] Source MAC (Ethernet Header): " +  packetData.get("SRC_MAC"));
         short ethType = buffer.getShort();
            packetData.put("ETH_TYPE", ethType);
            /*
            if (ethType > 0){
                String ethTypeString = PacketUtils.parseEtherType(ethType);
                packetData.put("ETH_TYPE", ethTypeString); // EtherType
            }
             */
     } catch (Exception e) {
         LOGGER.warning("Ethernet header parsing failed: " + e.getMessage());
     }
 }
 private static void parseWiFiHeader(ByteBuffer buffer, Map<String, Object> packetData) {
     try {
         buffer.position(0);  // Wi-Fi headers start from beginning if this is a raw frame
         short frameControl = buffer.getShort(); 
         packetData.put("WIFI_FRAME_CONTROL", frameControl); //  Frame Control field
         System.out.println("[DEBUG] Frame Control (Wi-Fi Header): " + packetData.get("WIFI_FRAME_CONTROL"));
         short duration = buffer.getShort();  
         packetData.put("WIFI_DURATION", duration); // Store duration 
         System.out.println("[DEBUG] Duration (Wi-Fi Header): " + packetData.get("WIFI_DURATION"));
         byte[] bssid = new byte[6]; // Assuming BSSID is right after duration
         buffer.get(bssid); 
         packetData.put("BSSID", PacketUtils.bytesToMac(bssid));
         System.out.println("[DEBUG] BSSID (Wi-Fi Header): " +  packetData.get("BSSID"));
         buffer.position(buffer.position() + 6); // Skip one MAC address
         short seqControl = buffer.getShort();
         packetData.put("SEQ_CONTROL", seqControl);
         System.out.println("[DEBUG] Sequence Control (Wi-Fi Header): " +  packetData.get("SEQ_CONTROL"));
     } catch (Exception e) {
         LOGGER.warning("Wi-Fi header parsing failed: " + e.getMessage());
     }
 }
 private static void parseIPv4(ByteBuffer buffer, int offset, Map<String, Object> packetData) {
     if (buffer.capacity() < offset + 20) {
         LOGGER.log(Level.WARNING, "Packet too short for IPv4 header.");
         return;
     }
     buffer.position(offset);
     int versionAndIhl = buffer.get() & 0xFF; // Version and IHL (Internet Header Length)
     int ihl = (versionAndIhl & 0x0F) * 4; // IHL (Internet Header Length in bytes)
     packetData.put("IP_VERSION", (versionAndIhl >> 4)); // Version (4 bits)
     System.out.println("[DEBUG] Version (IPv4 Header): " +  packetData.get("IP_VERSION"));
     buffer.get();  // Skip DSCP/ECN fields
     int totalLength = buffer.getShort() & 0xFFFF; // Total Length
     buffer.getShort(); // Identification (skip or log if needed)
     int flagsAndOffset = buffer.getShort() & 0xFFFF;
     int flags = (flagsAndOffset >> 13) & 0x07;
     int fragmentOffset = flagsAndOffset & 0x1FFF;
     packetData.put("IP_FLAGS", flags); // Flags (3 bits)
     System.out.println("[DEBUG] Flags (IPv4 Header): " + packetData.get("IP_FLAGS"));
     packetData.put("FRAGMENT_OFFSET", fragmentOffset); // Fragment Offset (in bytes)
     System.out.println("[DEBUG] Fragment Offset (IPv4 Header): " +  packetData.get("FRAGMENT_OFFSET"));
     packetData.put("TTL", buffer.get() & 0xFF); // TTL
     System.out.println("[DEBUG] TTL (IPv4 Header): " + packetData.get("TTL")); 
     int protocol = buffer.get() & 0xFF; 
     packetData.put("PROTOCOL", PacketUtils.parseProtocol(protocol)); // Protocol (TCP, UDP, ICMP, etc.)
     System.out.println("[DEBUG] Protocol (IPv4 Header): " + packetData.get("PROTOCOL"));
     packetData.put("IP_CHECKSUM", buffer.getShort() & 0xFFFF); // Header Checksum
     System.out.println("[DEBUG] Checksum (IPv4 Header): " + packetData.get("IP_CHECKSUM"));
     packetData.put("SRC_IP", PacketUtils.getIpAddress(buffer, offset + 12)); // Source IP (4 bytes)
     System.out.println("[DEBUG] Source IP (IPv4 Header): " + packetData.get("SRC_IP"));
     packetData.put("DEST_IP", PacketUtils.getIpAddress(buffer, offset + 16)); // Destination IP (4 bytes)
     System.out.println("[DEBUG] Destination IP (IPv4 Header): " + packetData.get("DEST_IP"));
     parseTransportLayer(buffer, offset + ihl, protocol, packetData); // Dispatch to transport layer parser based on protocol and header length
 }
 private static void parseIPv6(ByteBuffer buffer, int offset, Map<String, Object> packetData) {
     if (buffer.remaining() < offset + 40) {
         LOGGER.log(Level.WARNING, "Packet too short for IPv6 header.");
         return;
     }
     buffer.position(offset);
     int vtcfl = buffer.getInt();
     int version = (vtcfl >> 28) & 0x0F; // Version (4 bits)
     packetData.put("IP_VERSION", version); // Version (4 bits)
     System.out.println("[DEBUG] Version (IPv6 Header): " + packetData.get("IP_VERSION"));
     packetData.put("TRAFFIC_CLASS", (vtcfl >> 20) & 0xFF); // Traffic Class (8 bits)
     System.out.println("[DEBUG] Traffic Class (IPv6 Header): " + packetData.get("TRAFFIC_CLASS"));
     packetData.put("FLOW_LABEL", vtcfl & 0xFFFFF); // flow label (20 bits)
     System.out.println("[DEBUG] Flow Label (IPv6 Header): " + packetData.get("FLOW_LABEL"));
     byte[] srcIp = new byte[16];
     buffer.get(srcIp);
     packetData.put("SRC_IP", PacketUtils.getIpAddress(srcIp, 0)); // Source IPv6 (16 bytes)
     System.out.println("[DEBUG] Source IP (IPv6 Header): " + packetData.get("SRC_IP"));
     byte[] destIp = new byte[16];
     buffer.get(destIp);
     packetData.put("DEST_IP", PacketUtils.getIpAddress(destIp, 0)); // Destination IPv6 (16 bytes)
     System.out.println("[DEBUG] Destination IP (IPv6 Header): " + packetData.get("DEST_IP"));
     packetData.put("HOP_LIMIT", buffer.get() & 0xFF); // Hop Limit
     System.out.println("[DEBUG] Hop Limit (IPv6 Header): " + packetData.get("HOP_LIMIT"));
     int nextHeader = buffer.get() & 0xFF; // Next Header        
     String extensionHeaders = PacketUtils.parseExtensionHeaders(buffer, offset + 40, nextHeader, packetData);
     packetData.put("EXTENSION_HEADERS", extensionHeaders);
     System.out.println("[DEBUG] Extension Headers (IPv6 Header): " + packetData.get("EXTENSION_HEADERS"));
     parseTransportLayer(buffer, offset + 40, nextHeader, packetData);
 }
 private static void parseARP(ByteBuffer buffer, int offset, Map<String, Object> packetData) {
     if (buffer.remaining() < offset + 28) return; // ARP Header is 28 bytes
     buffer.position(offset);
     packetData.put("HTYPE", buffer.getShort(offset) & 0xFFFF); // Hardware type
     System.out.println("[DEBUG] Hardware Type (ARP Header): " + packetData.get("HTYPE"));
     packetData.put("PTYPE", buffer.getShort(offset + 2) & 0xFFFF); // Protocol type
     System.out.println("[DEBUG] Protocol Type (ARP Header): " + packetData.get("PTYPE"));
     packetData.put("HLEN", buffer.get(offset + 4) & 0xFF); // Hardware address length
     System.out.println("[DEBUG] Hardware Address Length (ARP Header): " + packetData.get("HLEN"));
     packetData.put("PLEN", buffer.get(offset + 5) & 0xFF); // Protocol address length
     System.out.println("[DEBUG] Protocol Address Length (ARP Header): " + packetData.get("PLEN"));
     int operation = buffer.getShort(offset + 6) & 0xFFFF; // Operation code (1 = request, 2 = reply)
     packetData.put("OPER", operation == 1 ? "REQUEST" : "REPLY"); // Operation type
     System.out.println("[DEBUG] Operation (ARP Header): " + packetData.get("OPER"));
     packetData.put("SRC_MAC", PacketUtils.getMacAddress(buffer, offset + 8)); // Source MAC
     System.out.println("[DEBUG] Source MAC (ARP Header): " + packetData.get("SRC_MAC"));
     packetData.put("SRC_IP", PacketUtils.getIpAddress(buffer, offset + 14)); // Source IP
     System.out.println("[DEBUG] Source IP (ARP Header): " + packetData.get("SRC_IP"));
     packetData.put("DEST_MAC", PacketUtils.getMacAddress(buffer, offset + 18)); // Destination MAC
     System.out.println("[DEBUG] Destination MAC (ARP Header): " + packetData.get("DEST_MAC"));
     packetData.put("DEST_IP", PacketUtils.getIpAddress(buffer, offset + 24)); // Destination IP
     System.out.println("[DEBUG] Destination IP (ARP Header): " + packetData.get("DEST_IP"));
 }    
 // Transport Layer (Layer 2)
 private static void parseTransportLayer(ByteBuffer buffer, int offset, int protocol, Map<String, Object> packetData) {
     switch (protocol) {
         case 6: parseTCP(buffer, offset, packetData); break;
         case 17: parseUDP(buffer, offset, packetData); break;
         case 1: parseICMP(buffer, offset, packetData); break;
         default:
             LOGGER.log(Level.INFO, "Unsupported Transport Layer Protocol: {0}", protocol);
     }
     try {
         if (protocol == 6 && buffer.remaining() >= offset + 20) { // TCP
             buffer.position(offset);
             int srcPort = buffer.getShort() & 0xFFFF;
             int destPort = buffer.getShort() & 0xFFFF;
             packetData.put("SRC_PORT", srcPort);
             System.out.println("[DEBUG] Source Port (TCP): " + packetData.get("SRC_PORT"));
             packetData.put("DEST_PORT", destPort);
             System.out.println("[DEBUG] Destination Port (TCP): " + packetData.get("DEST_PORT"));
             buffer.position(offset + 12); // Data offset field starts at byte 12
             int dataOffset = (buffer.get() >> 4) * 4; // TCP header length
             int appOffset = offset + dataOffset;
             // Application Layer Parsing for TCP
             if (buffer.limit() >= appOffset) {
                 buffer.position(appOffset);
                 if (srcPort == 80 || destPort == 80) {
                     parseHTTP(buffer.slice(), packetData);
                 } else if (srcPort == 443 || destPort == 443) {
                     parseTLS(buffer.slice(), packetData);
                 } else if (srcPort == 53 || destPort == 53) {
                     parseDNS(buffer.slice(), packetData);
                 }
             }
         } else if (protocol == 17 && buffer.remaining() >= offset + 8) { // UDP
             buffer.position(offset);
             int srcPort = buffer.getShort() & 0xFFFF;
             int destPort = buffer.getShort() & 0xFFFF;
             packetData.put("SRC_PORT", srcPort);
             System.out.println("[DEBUG] Source Port (UDP): " + packetData.get("SRC_PORT"));
             packetData.put("DEST_PORT", destPort);
             System.out.println("[DEBUG] Destination Port (UDP): " + packetData.get("DEST_PORT"));
             int appOffset = offset + 8;
             if (buffer.limit() >= appOffset) {
                 buffer.position(appOffset);
                 if (srcPort == 53 || destPort == 53) {
                     parseDNS(buffer.slice(), packetData);
                 }
             } 
    
         }
     } catch (Exception e) {
         LOGGER.warning("Transport layer parsing failed: " + e.getMessage());
     }
 }
 private static void parseTCP(ByteBuffer buffer, int offset, Map<String, Object> packetData) {
     if (buffer.capacity() < offset + 20) return;
     buffer.position(offset);
     long sequenceNum = buffer.getInt() & 0xFFFFFFFFL;
     long ackNum = buffer.getInt() & 0xFFFFFFFFL;
     int dataOffset = ((buffer.get() & 0xFF) >> 4) * 4; // data offset (header length in bytes)
     int flags = buffer.get() & 0xFF;
     int windowSize = buffer.getShort() & 0xFFFF;
     int checksum = buffer.getShort() & 0xFFFF;
     packetData.put("SEQUENCE_NUM", sequenceNum);
     System.out.println("[DEBUG] Sequence Number (TCP): " + packetData.get("SEQUENCE_NUM"));
     packetData.put("ACK_NUM", ackNum);
     System.out.println("[DEBUG] Acknowledgment Number (TCP): " + packetData.get("ACK_NUM"));
     //packetData.put("TCP_HEADER_LENGTH", dataOffset);
     packetData.put("TCP_FLAGS", PacketUtils.parseTCPFlags(flags));
     System.out.println("[DEBUG] TCP Flags (TCP): " + packetData.get("TCP_FLAGS"));
     packetData.put("WINDOW_SIZE", windowSize);
     System.out.println("[DEBUG] Window Size (TCP): " + packetData.get("WINDOW_SIZE"));
     packetData.put("TCP_CHECKSUM", checksum);
     System.out.println("[DEBUG] TCP Checksum (TCP): " + packetData.get("TCP_CHECKSUM"));

     if (dataOffset > 20) {
         byte[] options = new byte[dataOffset - 20];
         buffer.get(options);
         packetData.put("TCP_OPTIONS", options);
         System.out.println("[DEBUG] TCP Options (TCP): " + new String(options));
     }
     // Check if there's a TCP payload (application data)
     if (buffer.remaining() > 0) {
         byte[] tcpPayload = new byte[buffer.remaining()];
         buffer.get(tcpPayload);
         packetData.put("TCP_PAYLOAD", new String(tcpPayload));
         System.out.println("[DEBUG] TCP Payload (TCP): " + new String(tcpPayload));
     }
 }
 private static void parseUDP(ByteBuffer buffer, int offset, Map<String, Object> packetData) {
     // Checking for buffer overflow
     if (buffer.capacity() < offset + 8) return;
     buffer.position(offset); 
     int checksum = buffer.getShort() & 0xFFFF;
     packetData.put("UDP_CHECKSUM", checksum);
     System.out.println("[DEBUG] UDP Checksum (UDP): " + packetData.get("UDP_CHECKSUM"));
 }
 private static void parseICMP(ByteBuffer buffer, int offset, Map<String, Object> packetData) {
     if (buffer.capacity() < offset + 8) return;
     buffer.position(offset);
     int type = buffer.get() & 0xFF;
     int code = buffer.get() & 0xFF;
     int checksum = buffer.getShort() & 0xFFFF;
     packetData.put("ICMP_TYPE", type);
     System.out.println("[DEBUG] ICMP Type (ICMP): " + packetData.get("ICMP_TYPE"));
     packetData.put("ICMP_CODE", code);
     System.out.println("[DEBUG] ICMP Code (ICMP): " + packetData.get("ICMP_CODE"));
     packetData.put("CHECKSUM", checksum);
     System.out.println("[DEBUG] ICMP Checksum (ICMP): " + packetData.get("CHECKSUM"));
     packetData.put("SEQUENCE_NUM", buffer.getShort() & 0xFFFF);
     System.out.println("[DEBUG] ICMP Sequence Number (ICMP): " + packetData.get("SEQUENCE_NUM"));
 } 
 private static void parseHTTP(ByteBuffer buffer, Map<String, Object> packetData) {
     byte[] byteArray = new byte[buffer.remaining()];
     buffer.get(byteArray);
     String packetStr = new String(byteArray); // Convert to String for HTTP content extraction
     String method = PacketUtils.parseHttpMethods(packetStr);
     packetData.put("http_method", method);
     System.out.println("[DEBUG] HTTP Method: " + packetData.get("http_method"));
     packetData.put("HOST", PacketUtils.extractHeader(packetStr, "Host:"));
     System.out.println("[DEBUG] Host: " + packetData.get("HOST"));
     packetData.put("user_agent", PacketUtils.extractHeader(packetStr, "User-Agent:"));
     System.out.println("[DEBUG] User-Agent: " + packetData.get("user_agent"));
     packetData.put("Auth",PacketUtils.extractHeader(packetStr, "Authorization:"));
     System.out.println("[DEBUG] Authorization: " + packetData.get("Auth"));
     packetData.put("ContentType", PacketUtils.extractHeader(packetStr, "Content-Type:"));
     System.out.println("[DEBUG] Content-Type: " + packetData.get("ContentType"));
 }
 private static void parseDNS(ByteBuffer buffer, Map<String, Object> packetData) {
     packetData.put("TransactionID", buffer.getShort()); // Transaction ID
     System.out.println("[DEBUG] Transaction ID (DNS): " + packetData.get("TransactionID"));
     packetData.put("Flags", buffer.getShort()); // Flags
     System.out.println("[DEBUG] Flags (DNS): " + packetData.get("Flags"));
     packetData.put("ResponseCode", buffer.get() & 0xFF); // Response Code
     System.out.println("[DEBUG] Response Code (DNS): " + packetData.get("ResponseCode"));
     packetData.put("query_type", buffer.getShort() & 0xFFFF); // Query Type (A, AAAA, etc.)
     System.out.println("[DEBUG] Query Type (DNS): " + packetData.get("query_type")); 
     byte[] question = new byte[buffer.remaining()];
     buffer.get(question);
     packetData.put("Question", new String(question)); // Question (domain name)
     System.out.println("[DEBUG] Question (DNS): " + packetData.get("Question"));
 }
 private static void parseTLS(ByteBuffer buffer, Map<String, Object> packetData) { 
     int tlsVersion = buffer.getShort() & 0xFFFF;
     int handshakeType = buffer.get(); // 1 byte for handshake type
     int contentType = buffer.get(); // 1 byte for content type (application data, handshake, etc.)
     packetData.put("TLS_VERSION", tlsVersion);
     System.out.println("[DEBUG] TLS Version: " + packetData.get("TLS_VERSION"));
     packetData.put("HANDSHAKE_TYPE", handshakeType);
     System.out.println("[DEBUG] Handshake Type: " + packetData.get("HANDSHAKE_TYPE"));
     packetData.put("CONTENT_TYPE", contentType);
     System.out.println("[DEBUG] Content Type: " + packetData.get("CONTENT_TYPE"));
 } 
}
/*
 * EXAMPLES
 * 
Packet received...
Packet received at: 2025-04-18 15:09:59.078
Packet size: 1242
Packet ID: 1792376370567800
Destination MAC (Ethernet Header): B8:1E:A4:BA:89:75
Source MAC (Ethernet Header): 20:0C:86:A6:62:10
EtherType (Ethernet Header): 2048
EtherType in Integer: 800
EtherType in Hex: 800
EtherType in Decimal: 2048
Version (IPv4 Header): 4
Flags (IPv4 Header): 2
Fragment Offset (IPv4 Header): 0
TTL (IPv4 Header): 59
Protocol (IPv4 Header): UDP
Checksum (IPv4 Header): 2060
Source IP (IPv4 Header): 208.103.161.1
Destination IP (IPv4 Header): 192.168.1.4
UDP Checksum (UDP): 443
Source Port (UDP): 443
Destination Port (UDP): 62659
 * 
 * 
 */