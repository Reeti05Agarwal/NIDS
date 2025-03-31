package com.network.security;

import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
//import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.sql.*;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

 

public class PSFinal2 {
    static Properties config = loadConfig("NetworkMonitor\\src\\main\\resources\\config.properties");
    private static final String DB_URL = config.getProperty("db.url");
    private static final String DB_USER = config.getProperty("db.user");
    private static final String DB_PASSWORD = config.getProperty("db.password");

    private static final Map<Integer, String> PROTOCOL_MAP = new HashMap<>();
    static {
        PROTOCOL_MAP.put(1, "ICMP");
        PROTOCOL_MAP.put(2, "IGMP");
        PROTOCOL_MAP.put(6, "TCP");
        PROTOCOL_MAP.put(17, "UDP");
        PROTOCOL_MAP.put(50, "ESP");
        PROTOCOL_MAP.put(51, "AH");
        PROTOCOL_MAP.put(47, "GRE");
        PROTOCOL_MAP.put(132, "SCTP");
    }

    public static void main(String[] args) {
        try {
            System.out.println("[DEBUG] Fetching available network interfaces...");
            PcapNetworkInterface device = getDevice();
            if (device == null) {
                System.out.println("[ERROR] No network interfaces found.");
                return;
            }
            
            System.out.println("[INFO] Selected Interface: " + (device != null ? device.getName() : "None"));
            
            int snapshotLength = 65536;
            int readTimeout = 50;
            final PcapHandle handle = device.openLive(snapshotLength, PromiscuousMode.PROMISCUOUS, readTimeout);
            
            PacketListener listener = packet -> {
                System.out.println("[DEBUG] Packet received...");
                // Get Packet Data
                Map<String, Object> parsedData = parsePacket(packet.getRawData());
                // Insert it into database
                processPacket(parsedData);
            };
            
            handle.loop(50, listener);
            handle.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    static PcapNetworkInterface getDevice() {
        try {
            return new NifSelector().selectNetworkInterface();
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static Properties loadConfig(String filePath) {
        Properties properties = new Properties();
        try (FileInputStream input = new FileInputStream(filePath)) {
            properties.load(input);
        } catch (IOException e) {
            System.err.println("[ERROR] Could not load config file: " + filePath);
            e.printStackTrace();
        }
        return properties;
    }

    static void processPacket(Map<String, Object> data) {
        if (data.isEmpty()) {
            System.err.println("[ERROR] Skipping invalid packet...");
            return;
        }

        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            String insertQuery = "INSERT INTO PACKETS (TIMESTAMP, SRC_IP, DEST_IP, PROTOCOL_NAME, TOTAL_LENGTH, TTL, SRC_MAC, DEST_MAC) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
            PreparedStatement stmt = conn.prepareStatement(insertQuery);
            
            stmt.setTimestamp(1, new Timestamp(System.currentTimeMillis())); // Current timestamp
            stmt.setString(2, (String) data.get("SRC_IP")); // Source IP
            stmt.setString(3, (String) data.get("DEST_IP")); // Destination IP
            stmt.setString(4, PROTOCOL_MAP.getOrDefault((Integer) data.get("PROTOCOL_NAME"), "UNKNOWN")); // Protocol Name
            stmt.setInt(5, (Integer) data.get("TOTAL_LENGTH")); // Total Length
            stmt.setInt(6, (Integer) data.get("TTL")); // TTL
            stmt.setString(7, (String) data.get("SRC_MAC")); // Source MAC
            stmt.setString(8, (String) data.get("DEST_MAC")); // Destination MAC
            
            //stmt.setString(9, (String) data.get("PAYLOAD"));
            //Flags
            //fragment Offset
            // Checksum
             
            
            // Handle PAYLOAD field safely
            if (data.get("PAYLOAD") != null) {
                stmt.setString(9, (String) data.get("PAYLOAD"));
            } else {
                stmt.setString(9, "NO DATA");
            }

            stmt.executeUpdate();
            System.out.println("[INFO] Packet inserted successfully.");
            System.out.println("[DEBUG] Payload: " + data.get("PAYLOAD"));

            
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    static void insertPayload(int packetId, String payload, Connection conn) {
        String insertPayloadQuery = "INSERT INTO Packet_Payloads (packet_id, payload) VALUES (?, ?)";
        try (PreparedStatement stmt = conn.prepareStatement(insertPayloadQuery)) {
            stmt.setInt(1, packetId);
            stmt.setString(2, payload);
            stmt.executeUpdate();
            System.out.println("[INFO] Payload stored for Packet ID: " + packetId);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static Map<String, Object> parsePacket(byte[] packet) {
        //INitializer
        Map<String, Object> packetData = new HashMap<>();
        if (packet.length < 34) {
            System.out.println("[ERROR] Packet is too short!");
            return packetData;
        }

        packetData.put("SRC_MAC", getMacAddress(packet, 6));
        packetData.put("DEST_MAC", getMacAddress(packet, 0));
        int ethType = ((packet[12] & 0xFF) << 8) | (packet[13] & 0xFF);
        
        if (ethType == 0x0800) {
            int version = (packet[14] >> 4) & 0xF;
            int ihl = (packet[14] & 0xF) * 4;
            int totalLength = ((packet[16] & 0xFF) << 8) | (packet[17] & 0xFF);
            int protocol = packet[23] & 0xFF;
            int ttl = packet[22] & 0xFF;
            
            packetData.put("VERSION", version);
            packetData.put("TOTAL_LENGTH", totalLength);
            packetData.put("PROTOCOL_NAME", protocol);
            packetData.put("TTL", ttl);
            packetData.put("SRC_IP", getIpAddress(packet, 26));
            packetData.put("DEST_IP", getIpAddress(packet, 30));

            // Extract Payload (Header length to total length)
            int payloadStart = 14 + ihl; // Ethernet header + IP header
            int payloadLength = totalLength - ihl;

            if (payloadStart < packet.length) {
                byte[] payload = new byte[Math.min(payloadLength, packet.length - payloadStart)];
                System.arraycopy(packet, payloadStart, payload, 0, payload.length);
                packetData.put("PAYLOAD", bytesToHex(payload));
            } else {
                packetData.put("PAYLOAD", "NO PAYLOAD");
            }
            
        }
        return packetData;
    }

    
    // Utility to convert bytes to hex
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString().trim();
    }

    private static String getMacAddress(byte[] packet, int start) {
        return String.format("%02X:%02X:%02X:%02X:%02X:%02X",
                packet[start] & 0xFF, packet[start + 1] & 0xFF, packet[start + 2] & 0xFF,
                packet[start + 3] & 0xFF, packet[start + 4] & 0xFF, packet[start + 5] & 0xFF);
    }

    private static String getIpAddress(byte[] packet, int start) {
        try {
            return InetAddress.getByAddress(new byte[]{packet[start], packet[start + 1], packet[start + 2], packet[start + 3]}).getHostAddress();
        } catch (UnknownHostException e) {
            return "Invalid IP";
        }
    }
}


