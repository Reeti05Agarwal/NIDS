package com.network.security.services;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;

public class PacketParserMain {
    private static final Logger LOGGER = Logger.getLogger(PacketParserMain.class.getName());

    public static void main(String[] args) {
        PacketSnifferService packetSnifferService = new PacketSnifferService();

        PcapNetworkInterface  device = packetSnifferService.getDevice();
        if (device == null) {
            LOGGER.log(Level.SEVERE, "No network device selected!");
            return;
        }

        PacketListener listener = packet -> {
            System.out.println("[DEBUG] Packet received...");
            // Get Packet Data
            Map<String, Object> parsedData = parsePacket(packet.getRawData());
            System.out.println(parsedData);
        };

        try {
            PcapHandle handle = packetSnifferService.startCapture(device, listener);
            handle.loop(50, listener);
            handle.close();
        } catch (PcapNativeException | NotOpenException | InterruptedException e) {
            LOGGER.log(Level.SEVERE, "Error during packet capture: ", e);
        }
    }

    public static Map<String, Object> parsePacket(byte[] packet) {
        Map<String, Object> packetData = new HashMap<>();

        // Ethernet header is 14 bytes
        if (packet == null || packet.length < 14) { 
            LOGGER.log(Level.WARNING, "Packet is null or too short.");
            return packetData;
        }

        // TimeStamp
        packetData.put("TIMESTAMP", new Timestamp(System.currentTimeMillis()));
        // Source and Destination MAC addresses
        packetData.put("SRC_MAC", PacketUtils.getMacAddress(packet, 6));
        packetData.put("DEST_MAC", PacketUtils.getMacAddress(packet, 0));
        // EtherType
        int ethType = ((packet[12] & 0xFF) << 8) | (packet[13] & 0xFF);
        packetData.put("ETH_TYPE", ethType);

        int offset = 14; // Ethernet header length
        
        switch (ethType) {
            case 0x0800: parseIPv4(packet, offset, packetData); break;  // IPv4
            case 0x86DD: parseIPv6(packet, offset, packetData); break;  // IPv6
            case 0x0806: parseARP(packet, offset, packetData); break;   // ARP
            case 0x8100: parseVLAN(packet, offset, packetData); break;  // VLAN
            default:
                LOGGER.log(Level.INFO, "Unsupported EtherType: {0}", Integer.toHexString(ethType));
                packetData.put("INFO", "Unsupported EtherType: " + Integer.toHexString(ethType));         
        }
        return packetData;
    }

    private static void parseTransportLayer(byte[] packet, int offset, int protocol, Map<String, Object> packetData) {
        switch (protocol) {
            case 6: parseTCP(packet, offset, packetData); break;
            case 17: parseUDP(packet, offset, packetData); break;
            case 1: parseICMP(packet, offset, packetData); break;
            default:
                LOGGER.log(Level.INFO, "Unsupported Transport Layer Protocol: {0}", protocol);
        }
    }

    private static void parseIPv4(byte[] packet, int offset, Map<String, Object> packetData) {
        if (packet.length < offset + 20) {
            LOGGER.log(Level.WARNING, "Packet too short for IPv4 header.");
            return;
        }

        int ihl = (packet[offset] & 0x0F) * 4;
        if (packet.length < offset + ihl) {
            LOGGER.log(Level.WARNING, "IPv4 packet too short for header length.");
            return;
        }

        packetData.put("SRC_IP", PacketUtils.getIpAddress(packet, offset + 12));
        packetData.put("DEST_IP", PacketUtils.getIpAddress(packet, offset + 16));
        packetData.put("TTL", packet[offset + 8] & 0xFF); 
        packetData.put("FRAGMENT_OFFSET", ((packet[offset + 6] & 0x1F) << 8) | (packet[offset + 7] & 0xFF));
        packetData.put("CHECKSUM", ((packet[offset + 10] & 0xFF) << 8) | (packet[offset + 11] & 0xFF));

        int protocol = packet[offset + 9] & 0xFF;
        packetData.put("PROTOCOL", protocol);  

        parseTransportLayer(packet, offset + ihl, protocol, packetData);
    }

    private static void parseIPv6(byte[] packet, int offset, Map<String, Object> packetData) {
        if (packet.length < offset + 40) {
            LOGGER.log(Level.WARNING, "Packet too short for IPv6 header.");
            return;
        }
        
        int trafficClass = ((packet[offset] & 0x0F) << 4) | ((packet[offset + 1] >> 4) & 0x0F);
        packetData.put("TRAFFIC_CLASS", trafficClass);
        // Source IP and Destination IP are 16 bytes each in IPv6
        packetData.put("SRC_IP", PacketUtils.getIpAddress(packet, offset + 8));
        packetData.put("DEST_IP", PacketUtils.getIpAddress(packet, offset + 24));
        // Hop Limit is 1 byte
        packetData.put("HOP_LIMIT", packet[offset + 7] & 0xFF);
        // Flow Label is 3 bytes (20 bits)
        int flowLabel = ((packet[offset + 1] & 0x0F) << 16) | ((packet[offset + 2] & 0xFF) << 8) | (packet[offset + 3] & 0xFF);
        packetData.put("FLOW_LABEL", flowLabel);
        // nextHeader is the next header type (8 bits)
        int nextHeader = packet[offset + 6] & 0xFF;
        
        // Parse Extension Headers if present
        parseExtensionHeaders(packet, offset + 40, nextHeader, packetData);

        parseTransportLayer(packet, offset + 40, nextHeader, packetData);
    }

    private static boolean isExtensionHeader(int nextHeader) {
        // IPv6 extension headers (RFC 8200)
        return nextHeader == 0  || // Hop-by-Hop Options
               nextHeader == 43 || // Routing Header
               nextHeader == 44 || // Fragment Header
               nextHeader == 50 || // Encapsulating Security Payload (ESP)
               nextHeader == 51 || // Authentication Header (AH)
               nextHeader == 60 || // Destination Options
               nextHeader == 135;  // Mobility Header
    }    

    private static void parseExtensionHeaders(byte[] packet, int offset, int nextHeader, Map<String, Object> packetData) {
        List<Integer> extensionHeaders = new ArrayList<>();

        while (isExtensionHeader(nextHeader)) {
            if (packet.length < offset + 2) return; // Prevent out-of-bounds access

            extensionHeaders.add(nextHeader);
            int headerLength = (packet[offset + 1] & 0xFF) * 8 + 8; // Length is in 8-byte units
            nextHeader = packet[offset] & 0xFF; // Next header type
            offset += headerLength;
        }

        packetData.put("EXTENSION_HEADERS", extensionHeaders);
    }

    // ARP is Responsible for mapping IP Addresses to MAC Addresses within a local network
    
    private static void parseARP(byte[] packet, int offset, Map<String, Object> packetData) {
        if (packet.length < offset + 28) return; // ARP Header is 28 bytes
    
        int operation = ((packet[offset + 6] & 0xFF) << 8) | (packet[offset + 7] & 0xFF);
    
        packetData.put("HTYPE", ((packet[offset] & 0xFF) << 8) | (packet[offset + 1] & 0xFF)); // Hardware type
        packetData.put("PTYPE", ((packet[offset + 2] & 0xFF) << 8) | (packet[offset + 3] & 0xFF)); // Protocol type
        packetData.put("HLEN", packet[offset + 4] & 0xFF); // Hardware address length
        packetData.put("PLEN", packet[offset + 5] & 0xFF); // Protocol address length
        packetData.put("OPER", operation); // Operation (1 for request, 2 for reply)
        packetData.put("SRC_MAC", PacketUtils.getMacAddress(packet, offset + 8)); // Source MAC
        packetData.put("SRC_IP", PacketUtils.getIpAddress(packet, offset + 14)); // Source IP
        packetData.put("DEST_MAC", PacketUtils.getMacAddress(packet, offset + 18)); // Destination MAC
        packetData.put("DEST_IP", PacketUtils.getIpAddress(packet, offset + 24)); // Destination IP
        packetData.put("ARP_OPERATION", operation == 1 ? "REQUEST" : "REPLY"); // Operation type
    }
    
    private static void parseVLAN(byte[] packet, int offset, Map<String, Object> packetData) {
        if (packet.length < offset + 4) return;
        int vlanID = ((packet[offset] & 0x0F) << 8) | (packet[offset + 1] & 0xFF);
        packetData.put("VLAN_ID", vlanID);
    }

    private static void parseTCP(byte[] packet, int offset, Map<String, Object> packetData) {
        if (packet.length < offset + 20) return;

        packetData.put("SRC_PORT", PacketUtils.getPort(packet, offset));
        packetData.put("DEST_PORT", PacketUtils.getPort(packet, offset + 2));
        packetData.put("SEQUENCE_NUM", PacketUtils.getInt32(packet, offset + 4));
        packetData.put("ACK_NUM", PacketUtils.getInt32(packet, offset + 8));
        // Window Size (16-bit)
        packetData.put("WINDOW_SIZE", ((packet[offset + 14] & 0xFF) << 8) | (packet[offset + 15] & 0xFF));
        
        // Flags (6 bits from byte 13) -> [URG, ACK, PSH, RST, SYN, FIN]
        int flags = packet[offset + 13] & 0x3F;
        packetData.put("FLAGS", PacketUtils.parseTCPFlags(flags));

        
    }

    private static void parseUDP(byte[] packet, int offset, Map<String, Object> packetData) {
        if (packet.length < offset + 8) return;
    
        packetData.put("SRC_PORT", ((packet[offset] & 0xFF) << 8) | (packet[offset + 1] & 0xFF));
        packetData.put("DEST_PORT", ((packet[offset + 2] & 0xFF) << 8) | (packet[offset + 3] & 0xFF));
        // Length (16-bit)
        packetData.put("LENGTH", ((packet[offset + 4] & 0xFF) << 8) | (packet[offset + 5] & 0xFF));
        // Checksum (16-bit)
        packetData.put("CHECKSUM", ((packet[offset + 6] & 0xFF) << 8) | (packet[offset + 7] & 0xFF));
        // Packet ID (since UDP doesn't have a unique packet ID field, we can generate one)
        packetData.put("PACKET_ID", System.nanoTime()); // Unique ID based on timestamp
    }
    
    private static void parseICMP(byte[] packet, int offset, Map<String, Object> packetData) {
        if (packet.length < offset + 8) return; // Minimum ICMP header size
    
        packetData.put("ICMP_TYPE", packet[offset] & 0xFF);
        packetData.put("ICMP_CODE", packet[offset + 1] & 0xFF);
        // Checksum (16-bit)
        packetData.put("CHECKSUM", ((packet[offset + 2] & 0xFF) << 8) | (packet[offset + 3] & 0xFF));
        // Packet ID (Extracted for Echo Request/Reply messages)
        packetData.put("PACKET_ID", ((packet[offset + 4] & 0xFF) << 8) | (packet[offset + 5] & 0xFF));
        // Sequence Number (Used in Echo requests/replies)
        packetData.put("SEQUENCE_NUM", ((packet[offset + 6] & 0xFF) << 8) | (packet[offset + 7] & 0xFF));
    }

    static class PacketUtils {
        static String getMacAddress(byte[] packet, int start) {
            return String.format("%02X:%02X:%02X:%02X:%02X:%02X", 
                    packet[start], packet[start + 1], packet[start + 2], 
                    packet[start + 3], packet[start + 4], packet[start + 5]);
        }

        static String getIpAddress(byte[] packet, int start) {
            try {
                return InetAddress.getByAddress(Arrays.copyOfRange(packet, start, start + 4)).getHostAddress();
            } catch (UnknownHostException e) {
                return "Invalid IP";
            }
        }

        static int getPort(byte[] packet, int start) {
            return ((packet[start] & 0xFF) << 8) | (packet[start + 1] & 0xFF);
        }

        static int getInt32(byte[] packet, int start) {
            return ((packet[start] & 0xFF) << 24) | ((packet[start + 1] & 0xFF) << 16) |
                ((packet[start + 2] & 0xFF) << 8) | (packet[start + 3] & 0xFF);
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
    }
}
