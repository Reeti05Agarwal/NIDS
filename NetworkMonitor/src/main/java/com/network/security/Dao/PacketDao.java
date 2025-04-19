package com.network.security.Dao;

import java.io.FileInputStream;
import java.io.IOException;
// import java.io.InputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.sql.SQLException;
import java.util.Map;
import java.util.Properties;

//import com.network.security.services.PacketPipelineService;

public class PacketDao{
    private static final String DB_URL = "jdbc:mysql://localhost:3306/network";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "Maria@mysql05";

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

    private static void insertLayer(Connection conn, String query, Object... params) throws SQLException {
        try (PreparedStatement stmt = conn.prepareStatement(query)) {
            for (int i = 0; i < params.length; i++) {
                stmt.setObject(i + 1, params[i]);
            }
            stmt.executeUpdate();
        }
    }

    public static void processPacket(Map<String, Object> data) {
        if (data.isEmpty()) {
            System.err.println("[ERROR] Skipping invalid packet...");
            return;
        }

        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            // Insert into Packet_Metadata
            String insertQuery_Packet_Metadata = "INSERT INTO Packet_Metadata (timestamp) VALUES (?)"; 
            try (PreparedStatement stmt = conn.prepareStatement(insertQuery_Packet_Metadata, Statement.RETURN_GENERATED_KEYS)) {
                stmt.setTimestamp(1, (data.get("TIMESTAMP") instanceof java.sql.Timestamp) ? (java.sql.Timestamp) data.get("TIMESTAMP") : null);
                stmt.executeUpdate();
                ResultSet rs = stmt.getGeneratedKeys();
                long packetID = -1;
                if (rs.next()) {
                    packetID = rs.getLong(1);
    
                    // Data Link Layer
                    insertLayer(conn, "INSERT INTO Data_Link_Layer (PacketID, srcMAC, destMAC) VALUES (?, ?, ?)", packetID, data.get("SRC_MAC"), data.get("DEST_MAC"));
                    insertLayer(conn, "INSERT INTO Ethernet_Header (PacketID, ETH_TYPE) VALUES (?, ?)", packetID, data.get("ETH_TYPE"));
                    insertLayer(conn, "INSERT INTO WiFi_Header (PacketID, WIFI_FRAME_CONTROL, BSSID, SEQ_CONTROL) VALUES (?, ?, ?, ?)",
                        packetID, data.get("WIFI_FRAME_CONTROL"), data.get("BSSID"), data.get("SEQ_CONTROL"));
    
                    // Network Layer
                    insertLayer(conn, "INSERT INTO Network_Layer (PacketID, srcIP, destIP) VALUES (?, ?, ?)", packetID, data.get("SRC_IP"), data.get("DEST_IP"));
                    insertLayer(conn, "INSERT INTO IPv4_Header (PacketID, TTL, FRAGMENT_OFFSET, CHECKSUM, PROTOCOL) VALUES (?, ?, ?, ?, ?)",
                        packetID, data.get("TTL"), data.get("FRAGMENT_OFFSET"), data.get("CHECKSUM"), data.get("PROTOCOL"));
                    insertLayer(conn, "INSERT INTO IPv6_Header (PacketID, TRAFFIC_CLASS, HOP_LIMIT, FLOW_LABEL, EXTENSION_HEADERS) VALUES (?, ?, ?, ?, ?)",
                        packetID, data.get("TRAFFIC_CLASS"), data.get("HOP_LIMIT"), data.get("FLOW_LABEL"), data.get("EXTENSION_HEADERS"));
                    insertLayer(conn, "INSERT INTO ARP_Header (PacketID, HTYPE, PTYPE, HLEN, PLEN, OPER, ARP_OPERATION) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        packetID, data.get("HTYPE"), data.get("PTYPE"), data.get("HLEN"), data.get("PLEN"), data.get("OPER"), data.get("ARP_OPERATION"));
    
                    // Transport Layer
                    insertLayer(conn, "INSERT INTO Transport_Layer (PacketID, SRC_PORT, DEST_PORT) VALUES (?, ?, ?)",
                        packetID, data.get("SRC_PORT"), data.get("DEST_PORT"));
                    insertLayer(conn, "INSERT INTO TCP_Header (PacketID, SEQUENCE_NUM, ACK_NUM, WINDOW_SIZE, FLAGS) VALUES (?, ?, ?, ?, ?)",
                        packetID, data.get("SEQUENCE_NUM"), data.get("ACK_NUM"), data.get("WINDOW_SIZE"), data.get("FLAGS"));
                    insertLayer(conn, "INSERT INTO UDP_Header (PacketID, LENGTH, CHECKSUM) VALUES (?, ?, ?)",
                        packetID, data.get("LENGTH"), data.get("CHECKSUM"));
                    insertLayer(conn, "INSERT INTO ICMP_Header (PacketID, ICMP_TYPE, ICMP_CODE, CHECKSUM, PACKET_ID, SEQUENCE_NUM) VALUES (?, ?, ?, ?, ?, ?)",
                        packetID, data.get("ICMP_TYPE"), data.get("ICMP_CODE"), data.get("CHECKSUM"), data.get("PACKET_ID"), data.get("SEQUENCE_NUM"));
    
                    // Application Layer
                    insertLayer(conn, "INSERT INTO Application_Layer (PacketID, App_Protocol) VALUES (?, ?)", packetID, data.get("App_Protocol"));
                    insertLayer(conn, "INSERT INTO HTTP_Header (PacketID, HTTP_METHOD, HOST, user_agent, Auth, ContentType) VALUES (?, ?, ?, ?, ?, ?)",
                        packetID, data.get("HTTP_METHOD"), data.get("HOST"), data.get("user_agent"), data.get("Auth"), data.get("ContentType"));
                    insertLayer(conn, "INSERT INTO DNS_Header (PacketID, query_type, response_code, TransactionID, Flags, Question) VALUES (?, ?, ?, ?, ?, ?)",
                        packetID, data.get("query_type"), data.get("response_code"), data.get("TransactionID"), data.get("Flags"), data.get("Question"));
                    insertLayer(conn, "INSERT INTO TLS_Header (PacketID, tls_version, handshake_type, ContentType) VALUES (?, ?, ?, ?)",
                        packetID, data.get("tls_version"), data.get("handshake_type"), data.get("ContentType"));
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
     
}
