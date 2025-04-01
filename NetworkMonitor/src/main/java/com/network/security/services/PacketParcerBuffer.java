package com.network.security.services;

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
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.NotOpenException;

import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNetworkInterface;

import com.network.security.packetTesters.PacketParserMain;

public class PacketParcerBuffer {
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
            handle.loop(100, listener);
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

        ByteBuffer buffer = ByteBuffer.wrap(packet).order(ByteOrder.BIG_ENDIAN);

        // TimeStamp
        packetData.put("TIMESTAMP", new Timestamp(System.currentTimeMillis()));

        // Source and Destination MAC addresses
        packetData.put("SRC_MAC", PacketUtils.getMacAddress(buffer, 6));
        packetData.put("DEST_MAC", PacketUtils.getMacAddress(buffer, 0));
        // EtherType
        buffer.position(12);
        int ethType = buffer.getShort() & 0xFFFF;
        packetData.put("ETH_TYPE", ethType);

        int offset = 14; // Ethernet header length
        
        switch (ethType) {
            case 0x0800: parseIPv4(buffer, offset, packetData); break;  // IPv4
            case 0x86DD: parseIPv6(buffer, offset, packetData); break;  // IPv6
            case 0x0806: parseARP(buffer, offset, packetData); break;   // ARP
            case 0x8100: parseVLAN(buffer, offset, packetData); break;  // VLAN
            default:
                LOGGER.log(Level.INFO, "Unsupported EtherType: {0}", Integer.toHexString(ethType));
                packetData.put("INFO", "Unsupported EtherType: " + Integer.toHexString(ethType));         
        }
        return packetData;
    }

    private static void parseTransportLayer(ByteBuffer buffer, int offset, int protocol, Map<String, Object> packetData) {
        switch (protocol) {
            case 6: parseTCP(buffer, offset, packetData); break;
            case 17: parseUDP(buffer, offset, packetData); break;
            case 1: parseICMP(buffer, offset, packetData); break;
            default:
                LOGGER.log(Level.INFO, "Unsupported Transport Layer Protocol: {0}", protocol);
        }
    }

    private static void parseIPv4(ByteBuffer buffer, int offset, Map<String, Object> packetData) {
        if (buffer.capacity() < offset + 20) {
            LOGGER.log(Level.WARNING, "Packet too short for IPv4 header.");
            return;
        }
    
        buffer.position(offset);
        int ihl = (buffer.get() & 0x0F) * 4; // IPv4 header length
    
        buffer.position(offset + 8);
        packetData.put("TTL", buffer.get() & 0xFF); 
    
        packetData.put("SRC_IP", PacketUtils.getIpAddress(buffer, offset + 12)); // Added offset argument
        packetData.put("DEST_IP", PacketUtils.getIpAddress(buffer, offset + 16)); // Added offset argument
    
        buffer.position(offset + 6);
        packetData.put("FRAGMENT_OFFSET", buffer.getShort() & 0xFFFF);
    
        buffer.position(offset + 10);
        packetData.put("CHECKSUM", buffer.getShort() & 0xFFFF);
    
        buffer.position(offset + 9);
        int protocol = buffer.get() & 0xFF;
        packetData.put("PROTOCOL", PacketUtils.parceProtocol(protocol));
    
        parseTransportLayer(buffer, offset + ihl, protocol, packetData);
    }
    

    private static void parseIPv6(ByteBuffer buffer, int offset, Map<String, Object> packetData) {
        if (buffer.remaining() < offset + 40) {
            LOGGER.log(Level.WARNING, "Packet too short for IPv6 header.");
            return;
        }
        
        int trafficClass = ((buffer.get(offset) & 0x0F) << 4) | ((buffer.get(offset + 1) >> 4) & 0x0F);
        packetData.put("TRAFFIC_CLASS", trafficClass);
        
        byte[] srcIp = new byte[16];
        buffer.position(offset + 8);
        buffer.get(srcIp);
        packetData.put("SRC_IP", PacketUtils.getIpAddress(srcIp, 0)); // Added offset argument
    
        byte[] destIp = new byte[16];
        buffer.get(destIp);
        packetData.put("DEST_IP", PacketUtils.getIpAddress(destIp, 0));
        
        packetData.put("HOP_LIMIT", buffer.get(offset + 7) & 0xFF);
        
        int flowLabel = ((buffer.get(offset + 1) & 0x0F) << 16) | ((buffer.get(offset + 2) & 0xFF) << 8) | (buffer.get(offset + 3) & 0xFF);
        packetData.put("FLOW_LABEL", flowLabel);
        
        int nextHeader = buffer.get(offset + 6) & 0xFF;
        
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

    // ARP is Responsible for mapping IP Addresses to MAC Addresses within a local network
    
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
    
    private static void parseVLAN(ByteBuffer buffer, int offset, Map<String, Object> packetData) {
        if (buffer.remaining() < offset + 4) return;
        int vlanID = (buffer.get(offset) & 0x0F) << 8 | (buffer.get(offset + 1) & 0xFF);
        packetData.put("VLAN_ID", vlanID);
    }

    private static void parseTCP(ByteBuffer buffer, int offset, Map<String, Object> packetData) {
        if (buffer.capacity() < offset + 20) return;

        buffer.position(offset);
        packetData.put("SRC_PORT", buffer.getShort() & 0xFFFF);
        packetData.put("DEST_PORT", buffer.getShort() & 0xFFFF);
        packetData.put("SEQUENCE_NUM", buffer.getInt());
        packetData.put("ACK_NUM", buffer.getInt());

        buffer.position(offset + 14);
        packetData.put("WINDOW_SIZE", buffer.getShort() & 0xFFFF);

        buffer.position(offset + 13);
        int flags = buffer.get() & 0x3F;
        packetData.put("FLAGS", PacketUtils.parseTCPFlags(flags));
    }

    private static void parseUDP(ByteBuffer buffer, int offset, Map<String, Object> packetData) {
        if (buffer.capacity() < offset + 8) return;

        buffer.position(offset);
        packetData.put("SRC_PORT", buffer.getShort() & 0xFFFF);
        packetData.put("DEST_PORT", buffer.getShort() & 0xFFFF);
        packetData.put("LENGTH", buffer.getShort() & 0xFFFF);
        packetData.put("CHECKSUM", buffer.getShort() & 0xFFFF);
        //packetData.put("PACKET_ID", System.nanoTime());
    }
    
    private static void parseICMP(ByteBuffer buffer, int offset, Map<String, Object> packetData) {
        if (buffer.capacity() < offset + 8) return;

        buffer.position(offset);
        packetData.put("ICMP_TYPE", buffer.get() & 0xFF);
        packetData.put("ICMP_CODE", buffer.get() & 0xFF);
        packetData.put("CHECKSUM", buffer.getShort() & 0xFFFF);
        packetData.put("PACKET_ID", buffer.getShort() & 0xFFFF);
        packetData.put("SEQUENCE_NUM", buffer.getShort() & 0xFFFF);
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
    }
}
