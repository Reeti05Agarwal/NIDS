package com.network.security.PacketSniffing;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
//import org.pcap4j.core.PcapNativeException;
//import org.pcap4j.core.NotOpenException;
//
//import org.pcap4j.core.PacketListener;
//import org.pcap4j.core.PcapHandle;
//import org.pcap4j.core.PcapNetworkInterface;

import com.network.security.ExtraPrograms.packetTesters.PacketParserMain;

/*
 * 1. Layered Packet Parsing
 * Protocol handling and Extensibility
 * 
 * IMPORVEMENT:
 * Buffer Overflow Protection
 */


public class PacketParcerBuffer {
    private static final Logger LOGGER = Logger.getLogger(PacketParserMain.class.getName());

    public static Map<String, Object> parsePacket(byte[] packet) {
        Map<String, Object> packetData = new HashMap<>();

        // Ethernet header is 14 bytes
        if (packet == null || packet.length < 14) { 
            LOGGER.log(Level.WARNING, "Packet is null or too short.");
            return packetData;
        }

        ByteBuffer buffer = ByteBuffer.wrap(packet).order(ByteOrder.BIG_ENDIAN);

        // TimeStamp
        packetData.put("TIMESTAMP", new Timestamp(System.currentTimeMillis()));
        
        // Ethernet Header
        parseEthernetHeader(buffer, packetData);
        // Process possible VLAN tag if EtherType is VLAN (0x8100)
        int ethType = (int)packetData.get("ETH_TYPE");

        

        // Frame Check Sequence (last 4 bytes of Ethernet frame, if present)
        
        int offset = 14; // Ethernet header length
        
        if (ethType == 0x8100) { // VLAN
            offset = parseVLAN(buffer, offset, packetData);
            // After VLAN header, the next two bytes represent the actual EtherType.
            ethType = (int)packetData.get("ETH_TYPE");
        }

        if (packet.length >= 18) {
            byte[] fcsBytes = new byte[4];
            System.arraycopy(packet, packet.length - 4, fcsBytes, 0, 4);
            long fcs = ByteBuffer.wrap(fcsBytes).getInt() & 0xFFFFFFFFL;
            packetData.put("FRAME_CHECK_SEQ", fcs);
        }


        switch (ethType) {
            case 0x0800: parseIPv4(buffer, offset, packetData); break;  // IPv4
            case 0x86DD: parseIPv6(buffer, offset, packetData); break;  // IPv6
            case 0x0806: parseARP(buffer, offset, packetData); break;   // ARP
            //case 0x8100: parseVLAN(buffer, offset, packetData); break;  // VLAN
            default:
                LOGGER.log(Level.INFO, "Unsupported EtherType: {0}", Integer.toHexString(ethType));
                packetData.put("INFO", "Unsupported EtherType: " + Integer.toHexString(ethType));         
        }

        return packetData;
    }

    private static void parseWiFiHeader(ByteBuffer buffer, Map<String, Object> packetData) {
        try {
            buffer.position(0);  // Wi-Fi headers start from beginning if this is a raw frame
    
            short frameControl = buffer.getShort(); // 2 bytes
            packetData.put("WIFI_FRAME_CONTROL", frameControl);
    
            short duration = buffer.getShort(); // Not storing, just skipping it
    
            byte[] bssid = new byte[6];
            buffer.get(bssid); // Assuming BSSID is right after duration
            packetData.put("BSSID", PacketUtils.bytesToMac(bssid));
    
            buffer.position(buffer.position() + 6); // Skip one MAC address
    
            short seqControl = buffer.getShort();
            packetData.put("SEQ_CONTROL", seqControl);
        } catch (Exception e) {
            LOGGER.warning("Wi-Fi header parsing failed: " + e.getMessage());
        }
    }

    // Ethernet Header
    private static void parseEthernetHeader(ByteBuffer buffer, Map<String, Object> packetData) {
        try {
            buffer.position(0);  // Ethernet headers start from beginning if this is a raw frame
    
            byte[] destMac = new byte[6];
            buffer.get(destMac); // Destination MAC address
            packetData.put("DEST_MAC", PacketUtils.bytesToMac(destMac));
    
            byte[] srcMac = new byte[6];
            buffer.get(srcMac); // Source MAC address
            packetData.put("SRC_MAC", PacketUtils.bytesToMac(srcMac));
    
            short ethType = buffer.getShort(); // EtherType
            packetData.put("ETH_TYPE", ethType);
        } catch (Exception e) {
            LOGGER.warning("Ethernet header parsing failed: " + e.getMessage());
        }
    }

    // Transport Layer
    private static void parseTransportLayer(ByteBuffer buffer, int offset, int protocol, Map<String, Object> packetData) {
        switch (protocol) {
            case 6: parseTCP(buffer, offset, packetData); break;
            case 17: parseUDP(buffer, offset, packetData); break;
            case 1: parseICMP(buffer, offset, packetData); break;
            default:
                LOGGER.log(Level.INFO, "Unsupported Transport Layer Protocol: {0}", protocol);
        }
    }

    private static int parseVLAN(ByteBuffer buffer, int offset, Map<String, Object> packetData) {
        // VLAN header is 4 bytes long.
        if (buffer.capacity() < offset + 4) {
            LOGGER.warning("Packet too short for VLAN header.");
            return offset;
        }
        buffer.position(offset);
        // First 2 bytes: Tag Control Information (TCI)
        int tci = buffer.getShort() & 0xFFFF;
        packetData.put("VLAN_TCI", tci);
        // Next 2 bytes: Encapsulated EtherType
        int innerEthType = buffer.getShort() & 0xFFFF;
        packetData.put("ETH_TYPE", innerEthType);
        offset += 4;
        return offset;
    }

    private static void parseIPv4(ByteBuffer buffer, int offset, Map<String, Object> packetData) {
        if (buffer.capacity() < offset + 20) {
            LOGGER.log(Level.WARNING, "Packet too short for IPv4 header.");
            return;
        }
    
        buffer.position(offset);
        int versionAndIhl = buffer.get() & 0xFF;
        int ihl = (versionAndIhl & 0x0F) * 4;
        packetData.put("IP_VERSION", (versionAndIhl >> 4));
        
        // Skip DSCP/ECN fields
        buffer.get(); 

        // Total Length
        int totalLength = buffer.getShort() & 0xFFFF;
        packetData.put("TOTAL_LENGTH", totalLength);
        
        // Identification (skip or log if needed)
        buffer.getShort();
  
        // Flags and Fragment Offset (16 bits)
        int flagsAndOffset = buffer.getShort() & 0xFFFF;
        int flags = (flagsAndOffset >> 13) & 0x07;
        int fragmentOffset = flagsAndOffset & 0x1FFF;
        packetData.put("IP_FLAGS", flags);
        packetData.put("FRAGMENT_OFFSET", fragmentOffset);
        
        // TTL
        packetData.put("TTL", buffer.get() & 0xFF);
        // Protocol
        int protocol = buffer.get() & 0xFF;
        packetData.put("PROTOCOL", PacketUtils.parseProtocol(protocol));
        // Header Checksum
        packetData.put("IP_CHECKSUM", buffer.getShort() & 0xFFFF);
        // Source IP (4 bytes)
        packetData.put("SRC_IP", PacketUtils.getIpAddress(buffer, offset + 12));
        // Destination IP (4 bytes)
        packetData.put("DEST_IP", PacketUtils.getIpAddress(buffer, offset + 16));
        
        // Dispatch to transport layer parser based on protocol and header length
        parseTransportLayer(buffer, offset + ihl, protocol, packetData);
    }
    

    private static void parseIPv6(ByteBuffer buffer, int offset, Map<String, Object> packetData) {
        if (buffer.remaining() < offset + 40) {
            LOGGER.log(Level.WARNING, "Packet too short for IPv6 header.");
            return;
        }
        
        buffer.position(offset);
        
        // IPv6 Version, Traffic Class, Flow Label
        int vtcfl = buffer.getInt();
        packetData.put("IP_VERSION", (vtcfl >> 28) & 0xF);
        packetData.put("TRAFFIC_CLASS", (vtcfl >> 20) & 0xFF);
        packetData.put("FLOW_LABEL", vtcfl & 0xFFFFF);
        
        // Source IPv6 (16 bytes)
        byte[] srcIp = new byte[16];
        buffer.get(srcIp);
        packetData.put("SRC_IP", PacketUtils.getIpAddress(srcIp, 0));
        
        // Destination IPv6 (16 bytes)
        byte[] destIp = new byte[16];
        buffer.get(destIp);
        packetData.put("DEST_IP", PacketUtils.getIpAddress(destIp, 0));
        
        // Hop Limit
        packetData.put("HOP_LIMIT", buffer.get() & 0xFF);
        // Next Header
        int nextHeader = buffer.get() & 0xFF;
        
        // Process any extension headers (if present)
        parseExtensionHeaders(buffer, offset + 40, nextHeader, packetData);
        parseTransportLayer(buffer, offset + 40, nextHeader, packetData);
    }
    
    private static boolean isExtensionHeader(int nextHeader) {
        return nextHeader == 0  || nextHeader == 43 || nextHeader == 44 || nextHeader == 50 || 
               nextHeader == 51 || nextHeader == 60 || nextHeader == 135;
    }
    
    private static void parseExtensionHeaders(ByteBuffer buffer, int offset, int nextHeader, Map<String, Object> packetData) {
        List<Integer> extensionHeaders = new ArrayList<>();
        
        while (isExtensionHeader(nextHeader)) {
            if (buffer.remaining() < offset + 2) return;
            
            extensionHeaders.add(nextHeader);
            int headerLength = (buffer.get(offset + 1) & 0xFF) * 8 + 8;
            nextHeader = buffer.get(offset) & 0xFF;
            offset += headerLength;
        }
        
        packetData.put("EXTENSION_HEADERS", extensionHeaders);
    }

    // ARP 
    //is Responsible for mapping IP Addresses to MAC Addresses within a local network
    private static void parseARP(ByteBuffer buffer, int offset, Map<String, Object> packetData) {
        if (buffer.remaining() < offset + 28) return; // ARP Header is 28 bytes
    
        int operation = buffer.getShort(offset + 6) & 0xFFFF;
    
        packetData.put("HTYPE", buffer.getShort(offset) & 0xFFFF); // Hardware type
        packetData.put("PTYPE", buffer.getShort(offset + 2) & 0xFFFF); // Protocol type
        packetData.put("HLEN", buffer.get(offset + 4) & 0xFF); // Hardware address length
        packetData.put("PLEN", buffer.get(offset + 5) & 0xFF); // Protocol address length
        packetData.put("OPER", operation); // Operation (1 for request, 2 for reply)
        packetData.put("SRC_MAC", PacketUtils.getMacAddress(buffer, offset + 8)); // Source MAC
        packetData.put("SRC_IP", PacketUtils.getIpAddress(buffer, offset + 14)); // Source IP
        packetData.put("DEST_MAC", PacketUtils.getMacAddress(buffer, offset + 18)); // Destination MAC
        packetData.put("DEST_IP", PacketUtils.getIpAddress(buffer, offset + 24)); // Destination IP
        packetData.put("ARP_OPERATION", operation == 1 ? "REQUEST" : "REPLY"); // Operation type
    }
    
    /*
    private static void parseVLAN(ByteBuffer buffer, int offset, Map<String, Object> packetData) {
        if (buffer.remaining() < offset + 4) return;
        int vlanID = (buffer.get(offset) & 0x0F) << 8 | (buffer.get(offset + 1) & 0xFF);
        packetData.put("VLAN_ID", vlanID);
    }
     */

    // TCP
    private static void parseTCP(ByteBuffer buffer, int offset, Map<String, Object> packetData) {
        if (buffer.capacity() < offset + 20) return;

        buffer.position(offset);
        int srcPort = buffer.getShort() & 0xFFFF;
        int destPort = buffer.getShort() & 0xFFFF;
        long sequenceNum = buffer.getInt() & 0xFFFFFFFFL;
        long ackNum = buffer.getInt() & 0xFFFFFFFFL;
        int dataOffset = ((buffer.get() & 0xFF) >> 4) * 4; // data offset (header length in bytes)
        int flags = buffer.get() & 0xFF;
        int windowSize = buffer.getShort() & 0xFFFF;
        int checksum = buffer.getShort() & 0xFFFF;
        int urgentPointer = buffer.getShort() & 0xFFFF;
        
        packetData.put("TCP_SRC_PORT", srcPort);
        packetData.put("TCP_DEST_PORT", destPort);
        packetData.put("SEQUENCE_NUM", sequenceNum);
        packetData.put("ACK_NUM", ackNum);
        packetData.put("TCP_HEADER_LENGTH", dataOffset);
        packetData.put("TCP_FLAGS", PacketUtils.parseTCPFlags(flags));
        packetData.put("WINDOW_SIZE", windowSize);
        packetData.put("TCP_CHECKSUM", checksum);
        packetData.put("URGENT_POINTER", urgentPointer);

        if (dataOffset > 20) {
            byte[] options = new byte[dataOffset - 20];
            buffer.get(options);
            packetData.put("TCP_OPTIONS", options);
        }
    
        // Check if there's a TCP payload (application data)
        if (buffer.remaining() > 0) {
            byte[] tcpPayload = new byte[buffer.remaining()];
            buffer.get(tcpPayload);
            packetData.put("TCP_PAYLOAD", tcpPayload);
        }

    }

    private static void parseUDP(ByteBuffer buffer, int offset, Map<String, Object> packetData) {
        // Checking for buffer overflow
        if (buffer.capacity() < offset + 8) return;

        buffer.position(offset);
        int srcPort = buffer.getShort() & 0xFFFF;
        int destPort = buffer.getShort() & 0xFFFF;
        int length = buffer.getShort() & 0xFFFF;
        int checksum = buffer.getShort() & 0xFFFF;
        
        packetData.put("UDP_SRC_PORT", srcPort);
        packetData.put("UDP_DEST_PORT", destPort);
        packetData.put("UDP_LENGTH", length);
        packetData.put("UDP_CHECKSUM", checksum);
        //packetData.put("PACKET_ID", System.nanoTime());
        
        //COUNT FOT UDP PACKETS
    }
    
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

    private static void parseHTTP(ByteBuffer buffer, Map<String, Object> packetData) {
        packetData.put("APP_PROTOCOL", "HTTP");
        packetData.put("PacketID", System.nanoTime()); // Generate PacketID

        // Parse HTTP-specific fields (simple example, you should extend this as needed)
        byte[] byteArray = new byte[buffer.remaining()];
        buffer.get(byteArray);
        String packetStr = new String(byteArray); // Convert to String for HTTP content extraction
        if (packetStr.contains("GET") || packetStr.contains("POST")) {
            packetData.put("http_method", packetStr.contains("GET") ? "GET" : "POST");
        }

        // Extract additional HTTP details (headers)
        packetData.put("HOST", extractHeader(packetStr, "Host:"));
        packetData.put("user_agent", extractHeader(packetStr, "User-Agent:"));
        packetData.put("Auth", extractHeader(packetStr, "Authorization:"));
        packetData.put("ContentType", extractHeader(packetStr, "Content-Type:"));
    }

    // Helper method to extract HTTP headers
    private static String extractHeader(String packetStr, String headerName) {
        int start = packetStr.indexOf(headerName);
        if (start == -1) return null;
        start += headerName.length();
        int end = packetStr.indexOf("\r\n", start);
        return packetStr.substring(start, end).trim();
    }

    // DNS Header parsing (Layer 3)
    private static void parseDNS(ByteBuffer buffer, Map<String, Object> packetData) {
        packetData.put("APP_PROTOCOL", "DNS");
        packetData.put("PacketID", System.nanoTime()); // Generate PacketID
        
        // Transaction ID, Flags, Response Code, Query Type, Question
        packetData.put("TransactionID", buffer.getShort()); // 2 bytes for Transaction ID
        packetData.put("Flags", buffer.getShort()); // 2 bytes for Flags
        packetData.put("ResponseCode", buffer.get() & 0xFF); // 1 byte for response code
        packetData.put("query_type", buffer.getShort() & 0xFFFF); // Query Type (A, AAAA, etc.)
        
        // Assuming Question is in the domain name form (e.g., www.example.com)
        byte[] question = new byte[buffer.remaining()];
        buffer.get(question);
        packetData.put("Question", new String(question));
    }

    // TLS Header parsing (Layer 3)
    private static void parseTLS(ByteBuffer buffer, Map<String, Object> packetData) {
        packetData.put("APP_PROTOCOL", "TLS");
        packetData.put("PacketID", System.nanoTime()); // Generate PacketID
         
        
        // TLS Version, Handshake Type, Content Type (simple example)
        int tlsVersion = buffer.getShort() & 0xFFFF;
        int handshakeType = buffer.get(); // 1 byte for handshake type
        int contentType = buffer.get(); // 1 byte for content type (application data, handshake, etc.)
        
        packetData.put("tls_version", tlsVersion);
        packetData.put("handshake_type", handshakeType);
        packetData.put("ContentType", contentType);
    }

    static class PacketUtils {
        static String getMacAddress(ByteBuffer buffer, int start) {
            buffer.position(start);
            byte[] mac = new byte[6];
            buffer.get(mac);
            return String.format("%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        }

        static String getIpAddress(ByteBuffer buffer, int offset) {
            byte[] ip = new byte[4];
            buffer.position(offset);
            buffer.get(ip);
            try {
                return InetAddress.getByAddress(ip).getHostAddress();
            } catch (UnknownHostException e) {
                return "Invalid IP";
            }
        }

        static String getIpAddress(byte[] ip, int offset) {
            try {
                return InetAddress.getByAddress(ip).getHostAddress();
            } catch (UnknownHostException e) {
                return "Invalid IP";
            }
        }

        static Map<String, Boolean> parseTCPFlags(int flags) {
            Map<String, Boolean> flagMap = new HashMap<>();
            flagMap.put("URG", (flags & 0x20) != 0);
            flagMap.put("ACK", (flags & 0x10) != 0);
            flagMap.put("PSH", (flags & 0x08) != 0);
            flagMap.put("RST", (flags & 0x04) != 0);
            flagMap.put("SYN", (flags & 0x02) != 0);
            flagMap.put("FIN", (flags & 0x01) != 0);
            return flagMap;
        }

        static String parceProtocol(int protocol) {
            Map<Integer, String> protocolMap = new HashMap<>();
            protocolMap.put(1, "ICMP");
            protocolMap.put(6, "TCP");
            protocolMap.put(17, "UDP");
            return protocolMap.get(protocol);
        }

        public static String bytesToMac(byte[] macBytes) {
            StringBuilder mac = new StringBuilder();
            for (byte b : macBytes) {
                mac.append(String.format("%02X", b));
                mac.append(":");
            }
            return mac.substring(0, mac.length() - 1);
        }
        
        static String parseProtocol(int protocol) {
            Map<Integer, String> protocolMap = new HashMap();
            protocolMap.put(1, "ICMP");
            protocolMap.put(6, "TCP");
            protocolMap.put(17, "UDP");
            // Extend with other protocols as needed.
            return protocolMap.getOrDefault(protocol, "UNKNOWN");

        } 
    }
}
