package com.network.security.PacketSniffing;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.sql.Timestamp;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import com.network.security.util.PacketUtils;

/*
 * 1. Layered Packet Parsing
 * Protocol handling and Extensibility
 * 
 * IMPORVEMENT: 
 * 3. Have Thread pooling
 * 4. Handle TCP Option  
 */


public class PacketParserBuffer {
    private static final Logger LOGGER = Logger.getLogger(PacketParserBuffer.class.getName());

    public static Map<String, Object> parsePacket(byte[] packet) {
        Map<String, Object> packetData = new HashMap<>();

        // Ethernet header is 14 bytes
        if (packet == null || packet.length < 14) { 
            LOGGER.log(Level.WARNING, "Packet is null or too short.");
            return packetData;
        }

        ByteBuffer buffer = ByteBuffer.wrap(packet).order(ByteOrder.BIG_ENDIAN);

        // Packet metadata (Layer 1)
        packetData.put("TIMESTAMP", new Timestamp(System.currentTimeMillis()));// TimeStamp
        packetData.put("PACKET_SIZE", packet.length); // Packet size
     
        // Data Link Layer (Layer 2)
        parseEthernetHeader(buffer, packetData);// Ethernet Header
        String ethType = (String) packetData.get("ETH_TYPE");
        
        int offset = 14;  
        // if (packet[0] == 0x08 && packet[1] == 0x00) { // Check for Wi-Fi frame control field
        //     parseWiFiHeader(buffer, packetData);
        //     offset = 24; // Adjust offset for Wi-Fi header length
        // } else {
        //     offset = 14; // Ethernet header length
        // }

        switch (ethType) {
            case "IPv4": parseIPv4(buffer, offset, packetData); break;  // IPv4
            case "IPv6": parseIPv6(buffer, offset, packetData); break;  // IPv6
            case "ARP": parseARP(buffer, offset, packetData); break;   // ARP
            default:
                LOGGER.log(Level.INFO, "Unsupported EtherType: {0}", ethType);
                packetData.put("INFO", "Unsupported EtherType: " + ethType);         
        }

        return packetData;
    }

    // Ethernet Header (Layer 3)
    /*
     * "DEST_MAC"
        "SRC_MAC"
        "ETH_TYPE"
     */
    private static void parseEthernetHeader(ByteBuffer buffer, Map<String, Object> packetData) {
        try {
            buffer.position(0);  // Ethernet headers start from beginning if this is a raw frame
    
            if (buffer.remaining() < 14) { // Buffer overflow protection for Ethernet header
                LOGGER.warning("Ethernet header too short.");
                return;
            }

            byte[] destMac = new byte[6];
            buffer.get(destMac); 
            packetData.put("DEST_MAC", PacketUtils.bytesToMac(destMac)); // Destination MAC address
    
            byte[] srcMac = new byte[6];
            buffer.get(srcMac); 
            packetData.put("SRC_MAC", PacketUtils.bytesToMac(srcMac)); // Source MAC address (String)
    
            short ethType = buffer.getShort(); 
            String eth_Type = PacketUtils.parseEtherType(ethType);
            packetData.put("ETH_TYPE", eth_Type); // EtherType
        } catch (Exception e) {
            LOGGER.warning("Ethernet header parsing failed: " + e.getMessage());
        }
    }

    // Wifi Header (Layer 3)
    /*
     * "WIFI_FRAME_CONTROL"
        "WIFI_DURATION"
        "BSSID"
        "SEQ_CONTROL"
     */
    private static void parseWiFiHeader(ByteBuffer buffer, Map<String, Object> packetData) {
        try {
            buffer.position(0);  // Wi-Fi headers start from beginning if this is a raw frame
    
            if (buffer.remaining() < 24) { // Buffer overflow protection for Wi-Fi header
                LOGGER.warning("Wi-Fi header too short.");
                return;
            }

            short frameControl = buffer.getShort(); 
            packetData.put("WIFI_FRAME_CONTROL", frameControl); //  Frame Control field
            short duration = buffer.getShort();  
            packetData.put("WIFI_DURATION", duration); // Store duration 
            byte[] bssid = new byte[6]; // Assuming BSSID is right after duration
            buffer.get(bssid); 
            packetData.put("BSSID", PacketUtils.bytesToMac(bssid));
            buffer.position(buffer.position() + 6); // Skip one MAC address
            short seqControl = buffer.getShort();
            packetData.put("SEQ_CONTROL", seqControl);
        } catch (Exception e) {
            LOGGER.warning("Wi-Fi header parsing failed: " + e.getMessage());
        }
    }

    // IPv4 Header (Layer 3)
    /*
     * "IP_VERSION" 
        "IP_FLAGS"
        "FRAGMENT_OFFSET"
        "TTL"
        "PROTOCOL"
        "SRC_IP"
        "DEST_IP"
     */
    private static void parseIPv4(ByteBuffer buffer, int offset, Map<String, Object> packetData) {
        if (buffer.capacity() < offset + 20) {
            LOGGER.log(Level.WARNING, "Packet too short for IPv4 header.");
            return;
        }
    
        buffer.position(offset);
        int versionAndIhl = buffer.get() & 0xFF; // Version and IHL (Internet Header Length)
        int ihl = (versionAndIhl & 0x0F) * 4; // IHL (Internet Header Length in bytes)
        packetData.put("IP_VERSION", (versionAndIhl >> 4)); // Version (4 bits)
        buffer.get();  // Skip DSCP/ECN fields
        int totalLength = buffer.getShort() & 0xFFFF; // Total Length
        //packetData.put("PAYLOAD_SIZE", totalLength);
        buffer.getShort(); // Identification (skip or log if needed)
        int flagsAndOffset = buffer.getShort() & 0xFFFF;
        int flags = (flagsAndOffset >> 13) & 0x07;
        int fragmentOffset = flagsAndOffset & 0x1FFF;
        packetData.put("IP_FLAGS", flags); // Flags (3 bits)
        packetData.put("FRAGMENT_OFFSET", fragmentOffset); // Fragment Offset (in bytes)
        packetData.put("TTL", buffer.get() & 0xFF); // TTL
        int protocol = buffer.get() & 0xFF; 
        packetData.put("PROTOCOL", PacketUtils.parseProtocol(protocol)); // Protocol (TCP, UDP, ICMP, etc.)
        packetData.put("IP_CHECKSUM", buffer.getShort() & 0xFFFF); // Header Checksum
        packetData.put("SRC_IP", PacketUtils.getIpAddress(buffer, offset + 12)); // Source IP (4 bytes)
        packetData.put("DEST_IP", PacketUtils.getIpAddress(buffer, offset + 16)); // Destination IP (4 bytes)
        
        parseTransportLayer(buffer, offset + ihl, protocol, packetData); // Dispatch to transport layer parser based on protocol and header length
    }
    
    // IPv6 Header (Layer 3)
    /*
     * "IP_VERSION"
        "TRAFFIC_CLASS"
        "FLOW_LABEL"
        "SRC_IP"
        "DEST_IP"
        "HOP_LIMIT"
        "NEXT_HEADER"
     */
    private static void parseIPv6(ByteBuffer buffer, int offset, Map<String, Object> packetData) {
        if (buffer.remaining() < offset + 40) {
            LOGGER.log(Level.WARNING, "Packet too short for IPv6 header.");
            return;
        }
        
        buffer.position(offset);
        
        int vtcfl = buffer.getInt();
        packetData.put("IP_VERSION", (vtcfl >> 28) & 0xF); // Version (4 bits)
        packetData.put("TRAFFIC_CLASS", (vtcfl >> 20) & 0xFF); // Traffic Class (8 bits)
        packetData.put("FLOW_LABEL", vtcfl & 0xFFFFF); // flow label (20 bits)
        byte[] srcIp = new byte[16];
        buffer.get(srcIp);
        packetData.put("SRC_IP", PacketUtils.getIpAddress(srcIp, 0)); // Source IPv6 (16 bytes)
        byte[] destIp = new byte[16];
        buffer.get(destIp);
        packetData.put("DEST_IP", PacketUtils.getIpAddress(destIp, 0)); // Destination IPv6 (16 bytes)
        packetData.put("HOP_LIMIT", buffer.get() & 0xFF); // Hop Limit
        int nextHeader = buffer.get() & 0xFF; // Next Header        
        // Process any extension headers (if present)
        List<Integer> extensionHeaders = PacketUtils.parseExtensionHeaders(buffer, offset + 40, nextHeader, packetData);
        packetData.put("EXTENSION_HEADERS", extensionHeaders);
        parseTransportLayer(buffer, offset + 40, nextHeader, packetData);
    }


    // ARP Header (Layer 3)
    //is Responsible for mapping IP Addresses to MAC Addresses within a local network
    /*
     * "HTYPE"
        "PTYPE"
        "HLEN"
        "PLEN"
        "OPER"
        "SRC_MAC"
        "SRC_IP"
        "DEST_MAC"
        "DEST_IP" 
     */
    private static void parseARP(ByteBuffer buffer, int offset, Map<String, Object> packetData) {
        if (buffer.remaining() < offset + 28) return; // ARP Header is 28 bytes

        buffer.position(offset);
        packetData.put("HTYPE", buffer.getShort(offset) & 0xFFFF); // Hardware type
        packetData.put("PTYPE", buffer.getShort(offset + 2) & 0xFFFF); // Protocol type
        packetData.put("HLEN", buffer.get(offset + 4) & 0xFF); // Hardware address length
        packetData.put("PLEN", buffer.get(offset + 5) & 0xFF); // Protocol address length
        int operation = buffer.getShort(offset + 6) & 0xFFFF; // Operation code (1 = request, 2 = reply)
        packetData.put("OPER", operation == 1 ? "REQUEST" : "REPLY"); // Operation type
        packetData.put("SRC_MAC", PacketUtils.getMacAddress(buffer, offset + 8)); // Source MAC
        packetData.put("SRC_IP", PacketUtils.getIpAddress(buffer, offset + 14)); // Source IP
        packetData.put("DEST_MAC", PacketUtils.getMacAddress(buffer, offset + 18)); // Destination MAC
        packetData.put("DEST_IP", PacketUtils.getIpAddress(buffer, offset + 24)); // Destination IP
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
                packetData.put("DEST_PORT", destPort);
    
                buffer.position(offset + 12); // Data offset field starts at byte 12
                int dataOffset = (buffer.get() >> 4) * 4; // TCP header length
                int appOffset = offset + dataOffset;
    
                // Application Layer Parsing for TCP
                if (buffer.limit() >= appOffset) {
                    buffer.position(appOffset);
                    if (srcPort == 80 || destPort == 80) {
                        packetData.put("APP_PROTOCOL", "HTTP");
                        parseHTTP(buffer.slice(), packetData);
                    } else if (srcPort == 443 || destPort == 443) {
                        packetData.put("APP_PROTOCOL", "HTTPS");
                        parseTLS(buffer.slice(), packetData);
                    } else if (srcPort == 53 || destPort == 53) {
                        packetData.put("APP_PROTOCOL", "DNS");
                        parseDNS(buffer.slice(), packetData);
                    }
                }
    
            } else if (protocol == 17 && buffer.remaining() >= offset + 8) { // UDP
                buffer.position(offset);
                int srcPort = buffer.getShort() & 0xFFFF;
                int destPort = buffer.getShort() & 0xFFFF;
                packetData.put("SRC_PORT", srcPort);
                packetData.put("DEST_PORT", destPort);
    
                int appOffset = offset + 8;
                if (buffer.limit() >= appOffset) {
                    buffer.position(appOffset);
                    if (srcPort == 53 || destPort == 53) {
                        packetData.put("APP_PROTOCOL", "DNS");
                        parseDNS(buffer.slice(), packetData);
                    }
                }
            }
        } catch (Exception e) {
            LOGGER.warning("Transport layer parsing failed: " + e.getMessage());
        }
    }
    
    // TCP (Layer 3)
    /* 
        "SEQUENCE_NUM"
        "ACK_NUM"
        "TCP_FLAGS"
        "WINDOW_SIZE"
        "TCP_CHECKSUM"
        "TCP_OPTIONS"
        "TCP_PAYLOAD"
     */
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
        packetData.put("ACK_NUM", ackNum);
        packetData.put("TCP_FLAGS", PacketUtils.parseTCPFlags(flags));
        packetData.put("WINDOW_SIZE", windowSize);
        packetData.put("TCP_CHECKSUM", checksum);
         

        // if (dataOffset > 20) {
        //     byte[] options = new byte[dataOffset - 20];
        //     buffer.get(options);
        //     packetData.put("TCP_OPTIONS", options);
        // }
    
        // Check if there's a TCP payload (application data)
        if (buffer.remaining() > 0) {
            byte[] tcpPayload = new byte[buffer.remaining()];
            buffer.get(tcpPayload);
            String TCPpayload = PacketUtils.decodePayload(tcpPayload); // Decode the payload if needed
            packetData.put("TCP_PAYLOAD", TCPpayload);
        }

    }

    // UDP (Layer 3)
    /*
     * "UDP_SRC_PORT"
        "UDP_DEST_PORT"
        "UDP_CHECKSUM"
     */
    private static void parseUDP(ByteBuffer buffer, int offset, Map<String, Object> packetData) {
        // Checking for buffer overflow
        if (buffer.capacity() < offset + 8) return;

        buffer.position(offset); 
        //int length = buffer.getShort() & 0xFFFF;
        int checksum = buffer.getShort() & 0xFFFF;
        //packetData.put("UDP_LENGTH", length);  // Includes both header (8 bytes) and payload
        //packetData.put("UDP_HEADER_SIZE", 8);  // Always 8 bytes
        packetData.put("UDP_CHECKSUM", checksum);
         
        //COUNT FOT UDP PACKETS
    }
    
    // ICMP (Layer 3)
    // Internet Control Message Protocol (ICMP) is used for network diagnostics and error reporting. 
    /*
     * "ICMP_TYPE"
        "ICMP_CODE"
        "CHECKSUM"
        "SEQUENCE_NUM"
     */
    private static void parseICMP(ByteBuffer buffer, int offset, Map<String, Object> packetData) {
        if (buffer.capacity() < offset + 8) return;

        buffer.position(offset);
        int type = buffer.get() & 0xFF;
        int code = buffer.get() & 0xFF;
        int checksum = buffer.getShort() & 0xFFFF;
        packetData.put("ICMP_TYPE", type);
        packetData.put("ICMP_CODE", code);
        packetData.put("CHECKSUM", checksum);
        packetData.put("SEQUENCE_NUM", buffer.getShort() & 0xFFFF);

        //COUNT FOT ICMP PACKETS
    
    }

    // HTTP Header parsing (Layer 3)
    /*
     * "http_method"
        "HOST"
        "user_agent"
        "Auth"
        "ContentType"
     */
    private static void parseHTTP(ByteBuffer buffer, Map<String, Object> packetData) {
        byte[] byteArray = new byte[buffer.remaining()];
        buffer.get(byteArray);
        String packetStr = new String(byteArray); // Convert to String for HTTP content extraction
        String method = PacketUtils.parseHttpMethods(packetStr);
        packetData.put("HTTP_METHOD", method);
        packetData.put("HOST", PacketUtils.extractHeader(packetStr, "Host:")); // Host potential values: 
        packetData.put("USER_AGENT", PacketUtils.extractHeader(packetStr, "User-Agent:"));
        packetData.put("AUTH",PacketUtils.extractHeader(packetStr, "Authorization:"));
        packetData.put("CONTENT_TYPE", PacketUtils.extractHeader(packetStr, "Content-Type:"));
    }

    // DNS Header parsing (Layer 3)
    /*
     * "TransactionID"
        "Flags"
        "ResponseCode"
        "query_type"
        "Question"
     */
    private static void parseDNS(ByteBuffer buffer, Map<String, Object> packetData) {
 
        packetData.put("TRANSACTION_ID", buffer.getShort()); // Transaction ID
        packetData.put("FLAGS", buffer.getShort()); // Flags
        packetData.put("RESPONSE_CODE", buffer.get() & 0xFF); // Response Code
        packetData.put("QUERY_TYPE", buffer.getShort() & 0xFFFF); // Query Type (A, AAAA, etc.) 
        byte[] question = new byte[buffer.remaining()];
        buffer.get(question);
        packetData.put("QUESTION", new String(question)); // Question (domain name)
    }

    // TLS Header parsing (Layer 3)
    /*
     * "TLS_VERSION"
        "HANDSHAKE_TYPE"
        "CONTENT_TYPE"
     */
    private static void parseTLS(ByteBuffer buffer, Map<String, Object> packetData) { 
        int tlsVersion = buffer.getShort() & 0xFFFF;
        int handshakeType = buffer.get(); // 1 byte for handshake type
        int contentType = buffer.get(); // 1 byte for content type (application data, handshake, etc.)
        
        packetData.put("TLS_VERSION", tlsVersion);
        packetData.put("HANDSHAKE_TYPE", handshakeType);
        packetData.put("CONTENT_TYPE", contentType);
    }

    //

     
}
