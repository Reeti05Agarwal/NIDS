package com.network.security.ExtraPrograms.DetectionTest;

import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.sql.*;
import java.util.HashMap;
import java.util.Map;

public class PreDetection2 {
    private static final String DB_URL = "jdbc:mysql://localhost:3306/nids";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "Maria@mysql05";

    private static final Map<Integer, String> PROTOCOL_MAP = new HashMap<>();
    private static final Map<String, Integer> udpCount = new HashMap<>();
    private static final Map<String, Integer> icmpCount = new HashMap<>();

    static {
        PROTOCOL_MAP.put(1, "ICMP");
        PROTOCOL_MAP.put(2, "IGMP");
        PROTOCOL_MAP.put(6, "TCP");
        PROTOCOL_MAP.put(17, "UDP");
        PROTOCOL_MAP.put(50, "ESP");
        PROTOCOL_MAP.put(51, "AH");
        PROTOCOL_MAP.put(47, "GRE");
        PROTOCOL_MAP.put(132, "SCTP");

        // Reset UDP and ICMP counts every 10 seconds
        new Thread(() -> {
            while (true) {
                try {
                    Thread.sleep(10000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
                udpCount.clear();
                icmpCount.clear();
            }
        }).start();
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

    static void processPacket(Map<String, Object> data) {
        if (isAnomalous(data)) {
            System.out.println("[INFO] Suspicious packet detected! Not storing in database.");
            return; // 🚨 Skip storing if packet is an anomaly
        }

        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            String insertQuery = "INSERT INTO PACKETS (TIMESTAMP, SRC_IP, DEST_IP, PROTOCOL_NAME, TOTAL_LENGTH, TTL, SRC_MAC, DEST_MAC) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
            PreparedStatement stmt = conn.prepareStatement(insertQuery);
            
            stmt.setTimestamp(1, new Timestamp(System.currentTimeMillis()));
            stmt.setString(2, (String) data.get("SRC_IP"));
            stmt.setString(3, (String) data.get("DEST_IP"));
            stmt.setString(4, PROTOCOL_MAP.getOrDefault((Integer) data.get("PROTOCOL_NAME"), "UNKNOWN"));
            stmt.setInt(5, (Integer) data.get("TOTAL_LENGTH"));
            stmt.setInt(6, (Integer) data.get("TTL"));
            stmt.setString(7, (String) data.get("SRC_MAC"));
            stmt.setString(8, (String) data.get("DEST_MAC"));
            //Flags
            //fragment Offset
            // Checksum
            // Payload
            
            stmt.executeUpdate();
            System.out.println("[INFO] Packet inserted successfully.");
            
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
            
        }
        return packetData;
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

    static boolean isAnomalous(Map<String, Object> data) {
        String srcIp = (String) data.get("SRC_IP");
        String destIp = (String) data.get("DEST_IP");
        int protocol = (Integer) data.get("PROTOCOL_NAME");
        int totalLength = (Integer) data.get("TOTAL_LENGTH");
        int ttl = (Integer) data.get("TTL");
    
        //Rule 1: Detect Unusually Large Packets (Possible DoS)
        if (totalLength > 1500) {
            System.out.println("[ALERT] Large packet detected from " + srcIp + " (Possible DoS attack!)");
            return true;
        }
    
        //Rule 2: Detect Suspicious TTL Values (Possible Spoofing)
        if (ttl < 10 || ttl > 255) {
            System.out.println("[ALERT] Suspicious TTL value detected from " + srcIp + " (Possible Spoofing!)");
            return true;
        }
    
        // Rule 3: Detect UDP Flood (High volume UDP packets)
        if (protocol == 17 && totalLength > 1000) {
            udpCount.put(srcIp, udpCount.getOrDefault(srcIp, 0) + 1);
            if (udpCount.get(srcIp) > 100) {
                System.out.println("[ALERT] UDP Flood detected from " + srcIp);
                return true;
            }
        }
    
        // Rule 4: Detect ICMP Flood (Excessive ICMP Requests)
        if (protocol == 1) {
            icmpCount.put(srcIp, icmpCount.getOrDefault(srcIp, 0) + 1);
            if (icmpCount.get(srcIp) > 50) {
                System.out.println("[ALERT] ICMP Flooding detected from " + srcIp);
                return true;
            }
        }
    
        // Rule 5: Block Private IPs in WAN Traffic (IP Spoofing)
        if (isPrivateIP(srcIp) && !isPrivateIP(destIp)) {
            System.out.println("[ALERT] Private IP " + srcIp + " communicating with public IP (Possible IP Spoofing)");
            return true;
        }
    
        return false; // No anomaly detected
    }

    public static boolean isPrivateIP(String ip) {
        return ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("172.16.") || ip.startsWith("172.31.");
    }

    static void logAnomaly(Map<String, Object> data, String attackType) {
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            String logQuery = "INSERT INTO ANOMALY_LOG (SRC_IP, DEST_IP, ATTACK_TYPE, DETAILS) VALUES (?, ?, ?, ?)";
            PreparedStatement stmt = conn.prepareStatement(logQuery);

            stmt.setString(1, (String) data.get("SRC_IP"));
            stmt.setString(2, (String) data.get("DEST_IP"));
            stmt.setString(3, attackType);
            stmt.setString(4, "Suspicious packet detected from " + data.get("SRC_IP"));

            stmt.executeUpdate();
            System.out.println("[ALERT] Logged anomaly in database.");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
    
    
}

