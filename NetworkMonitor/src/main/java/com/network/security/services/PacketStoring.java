package com.network.security.services;

import java.io.FileInputStream;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.Map;
import java.util.Properties;

public class PacketStoring {
    static Properties config = loadConfig("NetworkMonitor\\src\\main\\resources\\config.properties");
    private static final String DB_URL = config.getProperty("db.url");
    private static final String DB_USER = config.getProperty("db.user");
    private static final String DB_PASSWORD = config.getProperty("db.password");

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
            // Super Table: Packet Metadata
            String insertQuery_Packet_Metadata = "INSERT INTO Packet_Metadata (PacketID, timestamp, srcIP, destIP, payloadSize) VALUES (?, ?, ?, ?, ?)"; 
            PreparedStatement stmt_Packet_Metadata = conn.prepareStatement(insertQuery_Packet_Metadata);
            stmt_Packet_Metadata.setTimestamp(1, (data.get("TIMESTAMP") instanceof java.sql.Timestamp) ? (java.sql.Timestamp) data.get("TIMESTAMP") : null); // Current timestamp
            stmt_Packet_Metadata.setString(4, (String) data.get("ETH_TYPE")); // Source IP
            stmt_Packet_Metadata.executeUpdate();

            // Data Link Layer
            String insertQuery_Data_Link_Layer = "INSERT INTO Data_Link_Layer (PacketID, srcMAC, destMAC, protocolType) VALUES (?, ?, ?, ?)";
            String insertQuery_Ethernet_Header = "INSERT INTO Ethernet_Header (PacketID, payload) VALUES (?, ?)";
            String insertQuery_WiFi_Header = "INSERT INTO WiFi_Header (PacketID, header) VALUES (?, ?)";
            PreparedStatement stmt_Data_Link_Layer  = conn.prepareStatement(insertQuery_Data_Link_Layer);
            stmt_Data_Link_Layer.setString(1, (String) data.get("SRC_MAC")); //  
            stmt_Data_Link_Layer.setString(2, (String) data.get("DEST_MAC")); //  
            stmt_Data_Link_Layer.executeUpdate();
            PreparedStatement stmt_Ethernet_Header = conn.prepareStatement(insertQuery_Ethernet_Header);
            stmt_Ethernet_Header.setTimestamp(1, data.get()); // Current timestamp
            stmt_Ethernet_Header.setString(2, data.get()); // Source IP
            stmt_Ethernet_Header.setString(3, (String) data.get("ETH_TYPE")); 
            stmt_Ethernet_Header.executeUpdate();
            PreparedStatement stmt_WiFi_Header = conn.prepareStatement(insertQuery_WiFi_Header);
            stmt_WiFi_Header.setTimestamp(1, data.get()); // Current timestamp
            stmt_WiFi_Header.setString(2, data.get()); // Source IP
            stmt_WiFi_Header.executeUpdate();

            // Network Layer
            String insertQuery_Network_Layer = "INSERT INTO Network_Layer (PacketID, srcIP, destIP, protocol) VALUES (?, ?, ?, ?)";
            String insertQuery_IPv4_Header = "INSERT INTO IPv4_Header (PacketID, protocol_type, ttl checksum, FragmentOffset, Options) VALUES (?, ?, ?, ?, ?)";
            String insertQuery_IPv6_Header = "INSERT INTO IPv6_Header (PacketID, flow_label, hop_limit, ExtensionHeaders) VALUES (?, ?, ?, ?)";
            String insertQuery_ARP_Header = "INSERT INTO ARP_Header (PacketID, flow_label, hop_limit, ExtensionHeaders) VALUES (?, ?, ?, ?)";
            PreparedStatement stmt_Network_Layer = conn.prepareStatement(insertQuery_Network_Layer);
            stmt_Network_Layer.setString(2, (String) data.get("SRC_IP"));   
            stmt_Network_Layer.setString(3, (String) data.get("DEST_IP"));
            stmt_Network_Layer.executeUpdate();
            PreparedStatement stmt_IPv4_Header = conn.prepareStatement(insertQuery_IPv4_Header);
            stmt_IPv4_Header.setString(2, (String) data.get("TTL"));  
            stmt_IPv4_Header.setString(2, (String) data.get("FRAGMENT_OFFSET"));  
            stmt_IPv4_Header.setString(1, (String) data.get("CHECKSUM"));  
            stmt_IPv4_Header.setString(2, (String) data.get("PROTOCOL")); 
            stmt_IPv4_Header.executeUpdate();
            PreparedStatement stmt_IPv6_Header = conn.prepareStatement(insertQuery_IPv6_Header);
            stmt_IPv6_Header.setString(1, (String) data.get("TRAFFIC_CLASS"));  
            stmt_IPv6_Header.setString(2, (String) data.get("HOP_LIMIT"));
            stmt_IPv6_Header.setString(2, (String) data.get("FLOW_LABEL")); 
            stmt_IPv6_Header.setString(2, (String) data.get("EXTENSION_HEADERS"));
            stmt_IPv6_Header.executeUpdate();
            PreparedStatement stmt_ARP_Header = conn.prepareStatement(insertQuery_IPv6_Header);  
            stmt_ARP_Header.setString(2, (String) data.get("HTYPE")); 
            stmt_ARP_Header.setString(2, (String) data.get("PTYPE")); 
            stmt_ARP_Header.setString(2, (String) data.get("HLEN")); 
            stmt_ARP_Header.setString(2, (String) data.get("PLEN")); 
            stmt_ARP_Header.setString(2, (String) data.get("OPER"));
            stmt_ARP_Header.setString(2, (String) data.get("ARP_OPERATION"));
            stmt_ARP_Header.executeUpdate();

            // Transport Layer
            String insertQuery_Transport_Layer = "INSERT INTO Transport_Layer (PacketID, srcPort, destPort) VALUES (?, ?, ?)";
            String insertQuery_TCP_Header = "INSERT INTO TCP_Header (PacketID, SequenceNum, AckNum, Flags, WindowsSize) VALUES (?, ?, ?, ?, ?)";
            String insertQuery_UDP_Header = "INSERT INTO UDP_Header (PacketID, Length, Checksum) VALUES (?, ?, ?)";
            String insertQuery_ICMP_Header = "INSERT INTO ICMP_Header (PacketID, type, code) VALUES (?, ?, ?)";
            PreparedStatement stmt_Transport_Layer = conn.prepareStatement(insertQuery_Transport_Layer);
            stmt_Transport_Layer.setString(1,(String) data.get("SRC_PORT")); // Current timestamp
            stmt_Transport_Layer.setString(2, (String) data.get("DEST_PORT")); // Source IP
            stmt_Transport_Layer.executeUpdate();
            PreparedStatement stmt_TCP_Header = conn.prepareStatement(insertQuery_TCP_Header);
            //stmt_TCP_Header.setString(1, (String) data.get("SRC_PORT")); // Current timestamp
            //stmt_TCP_Header.setString(2, (String) data.get("DEST_PORT"));  
            stmt_TCP_Header.setInt(2, (Integer) data.get("SEQUENCE_NUM")); // Source I
            stmt_TCP_Header.setString(2, (String) data.get("ACK_NUM")); // Source I
            stmt_TCP_Header.setShort(2, (Short) data.get("WINDOW_SIZE")); // Source I
            stmt_TCP_Header.setString(2, (String) data.get("FLAGS")); // Source I
            stmt_TCP_Header.executeUpdate();
            PreparedStatement stmt_UDP_Header = conn.prepareStatement(insertQuery_UDP_Header);
            stmt_UDP_Header.setShort(1, (Short) data.get("LENGTH")); // Current timestamp
            stmt_UDP_Header.setShort(2, (Short) data.get("CHECKSUM")); // Source IP
            stmt_UDP_Header.executeUpdate();
            PreparedStatement stmt_ICMP_Header = conn.prepareStatement(insertQuery_ICMP_Header);
            stmt_ICMP_Header.setString(1, (String)data.get("ICMP_TYPE")); // Current timestamp
            stmt_ICMP_Header.setString(2, (String) data.get("ICMP_CODE")); // Source IP
            stmt_ICMP_Header.setShort(2, (Short) data.get("CHECKSUM"));
            stmt_ICMP_Header.setShort(2, (Short) data.get("PACKET_ID"));
            stmt_ICMP_Header.setShort(2, (Short) data.get("SEQUENCE_NUM"));
            stmt_ICMP_Header.executeUpdate();

            // Application Layer
            String insertQuery_Application_Layer = "INSERT INTO Application_Layer (PacketID, App_Protocol) VALUES (?, ?)";
            String insertQuery_HTTP_Header = "INSERT INTO HTTP_Header (PacketID, http_method, host, user_agent, Auth, ContentType) VALUES (?, ?, ?, ?, ?, ?)";
            String insertQuery_DNS_Header = "INSERT IqNTO DNS_Header (PacketID, query_type, response_code, TransactionID, Flags, Question) VALUES (?, ?, ?, ?, ?, ?)";
            String insertQuery_TLS_Header = "INSERT INTO TLS_Header (PacketID, tls_version, handshake_type, ContentType) VALUES (?, ?, ?, ?)";
            PreparedStatement stmt_Application_Layer = conn.prepareStatement(insertQuery_Application_Layer);
            PreparedStatement stmt_HTTP_Header = conn.prepareStatement(insertQuery_HTTP_Header);
            PreparedStatement stmt_DNS_Header = conn.prepareStatement(insertQuery_DNS_Header);
            PreparedStatement stmt_TLS_Header = conn.prepareStatement(insertQuery_TLS_Header);
             
            System.out.println("[INFO] Packet inserted successfully.");
        
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

     
}
