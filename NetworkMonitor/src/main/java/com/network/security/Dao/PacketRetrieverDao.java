package com.network.security.Dao;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;
import java.util.Map;

public class PacketRetrieverDao {

    private static final String DB_URL = "jdbc:mysql://localhost:3306/network";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "root";

    public static Map<String, Object> getPacketData(long packetID) {
        Map<String, Object> packetData = new HashMap<>();

        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {

            // Packet Metadata
            try (PreparedStatement stmt = conn.prepareStatement("SELECT * FROM Packet_Metadata WHERE PacketID = ?")) {
                stmt.setLong(1, packetID);
                ResultSet rs = stmt.executeQuery();
                if (rs.next()) {
                    packetData.put("TIMESTAMP", rs.getTimestamp("timestamp"));
                    packetData.put("PACKET_SIZE", rs.getInt("payloadsize"));
                }
            }

            // Data Link Layer
            retrieveFields(conn, packetData, "Data_Link_Layer", packetID, "srcMAC", "destMAC");
            retrieveFields(conn, packetData, "Ethernet_Header", packetID, "ETH_TYPE");
            retrieveFields(conn, packetData, "WiFi_Header", packetID, "FRAME_CONTROL", "BSSID", "SEQ_CONTROL");

            // Network Layer
            retrieveFields(conn, packetData, "Network_Layer", packetID, "srcIP", "destIP");
            retrieveFields(conn, packetData, "IPv4_Header", packetID, "IP_VERSION", "IP_FLAGS", "TTL", "CHECKSUM", "PROTOCOL");
            retrieveFields(conn, packetData, "IPv6_Header", packetID, "IP_VERSION", "TRAFFIC_CLASS", "HOP_LIMIT", "FLOW_LABEL", "EXTENSIONHEADERS");
            retrieveFields(conn, packetData, "ARP_Header", packetID, "HTYPE", "PTYPE", "HLEN", "PLEN", "OPER", "ARP_OPERATION");

            // Transport Layer
            retrieveFields(conn, packetData, "Transport_Layer", packetID, "srcPort", "destPort");
            retrieveFields(conn, packetData, "TCP_Header", packetID, "SequenceNum", "AckNum", "WindowsSize", "FLAGS", "CHECKSUM", "PAYLOAD", "options");
            retrieveFields(conn, packetData, "UDP_Header", packetID, "CHECKSUM");
            retrieveFields(conn, packetData, "ICMP_Header", packetID, "TYPE", "CODE", "CHECKSUM", "SEQUENCE_NUM");

            // Application Layer
            retrieveFields(conn, packetData, "Application_Layer", packetID, "App_Protocol");
            retrieveFields(conn, packetData, "HTTP_Header", packetID, "HTTP_METHOD", "HOST", "user_agent", "Auth", "ContentType");
            retrieveFields(conn, packetData, "DNS_Header", packetID, "query_type", "response_code", "TransactionID", "Flags", "Question");
            retrieveFields(conn, packetData, "TLS_Header", packetID, "tls_version", "handshake_type", "ContentType");

        } catch (SQLException e) {
            e.printStackTrace();
        }

        return packetData;
    }

    private static void retrieveFields(Connection conn, Map<String, Object> map, String table, long packetID, String... fields) {
        StringBuilder query = new StringBuilder("SELECT ");
        for (int i = 0; i < fields.length; i++) {
            query.append(fields[i]);
            if (i != fields.length - 1) {
                query.append(", ");
            }
        }
        query.append(" FROM ").append(table).append(" WHERE PacketID = ?");

        try (PreparedStatement stmt = conn.prepareStatement(query.toString())) {
            stmt.setLong(1, packetID);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                for (String field : fields) {
                    map.put(field, rs.getObject(field));
                }
            }
        } catch (SQLException e) {
            System.err.println("Error retrieving from " + table + ": " + e.getMessage());
        }
    }

    // Optionally, fetch the latest PacketID
    public static long getLatestPacketID() {
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD); Statement stmt = conn.createStatement(); ResultSet rs = stmt.executeQuery("SELECT MAX(PacketID) AS maxID FROM Packet_Metadata")) {
            if (rs.next()) {
                return rs.getLong("maxID");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return -1;
    }
}
