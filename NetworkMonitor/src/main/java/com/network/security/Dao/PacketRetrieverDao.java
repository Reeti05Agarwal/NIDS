package com.network.security.Dao;

import java.sql.*;
import java.util.HashMap;
import java.util.Map;
import com.network.security.util.DBConnection;

public class PacketRetrieverDao {
    public static void main(String[] args) {
        long packetID = PacketRetrieverDao.getLatestPacketID(); // or hardcode a known ID
        System.out.println("Testing PacketID: " + packetID);

        Map<String, Object> data = PacketRetrieverDao.getPacketData(packetID);

        for (Map.Entry<String, Object> entry : data.entrySet()) {
            System.out.println(entry.getKey() + " => " + entry.getValue());
        }
    }

    public static Map<String, Object> getPacketData(long packetID) {
        Map<String, Object> packetData = new HashMap<>();

        try (Connection conn = DBConnection.getConnection()) {

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
            String ethType = (String) packetData.get("ETH_TYPE");
            System.out.println("[RETRIEVER] Eth_Type" + ethType);
            if (ethType != null) {
                switch (ethType) {
                    case "IPv4":
                        retrieveFields(conn, packetData, "IPv4_Header", packetID, "IP_VERSION", "IP_FLAGS", "TTL", "CHECKSUM", "PROTOCOL");
                        break;
                    case "IPv6":
                        retrieveFields(conn, packetData, "IPv6_Header", packetID, "IP_VERSION", "TRAFFIC_CLASS", "HOP_LIMIT", "FLOW_LABEL", "EXTENSIONHEADERS");
                        break;
                    case "ARP":
                        retrieveFields(conn, packetData, "ARP_Header", packetID, "HTYPE", "PTYPE", "HLEN", "PLEN", "OPER", "ARP_OPERATION");
                        break;
                    default:
                        System.out.println("Unknown ETH_TYPE: " + ethType);
                        

                }
            } else {
                return packetData;
            }

            // Transport Layer
            retrieveFields(conn, packetData, "Transport_Layer", packetID, "srcPort", "destPort");
            String Protocol = (String) packetData.get("PROTOCOL");
            if (Protocol!=null){
                switch (Protocol) {
                    case "TCP":
                        retrieveFields(conn, packetData, "TCP_Header", packetID, "SequenceNum", "AckNum", "WindowsSize", "FLAGS", "CHECKSUM", "PAYLOAD", "options");
                        break;
                    case "UDP":
                        retrieveFields(conn, packetData, "UDP_Header", packetID, "CHECKSUM");
                        break;
                    case "ICMP":
                        retrieveFields(conn, packetData, "ICMP_Header", packetID, "TYPE", "CODE", "CHECKSUM", "SEQUENCE_NUM");
                        break;
                }
            }else{
                System.out.println("[RETRIEVER] Protocol is NULL");
            }
            

            // Application Layer
            retrieveFields(conn, packetData, "Application_Layer", packetID, "App_Protocol");
            String App_Protocol = (String) packetData.get("App_Protocol");
            switch (App_Protocol) {
                case "HTTP": 
                    retrieveFields(conn, packetData, "HTTP_Header", packetID, "HTTP_METHOD", "HOST", "user_agent", "Auth", "ContentType");
                    break;    
                case "HTTPS":
                    retrieveFields(conn, packetData, "DNS_Header", packetID, "query_type", "response_code", "TransactionID", "Flags", "Question");
                    break;    
                case "DNS":
                    retrieveFields(conn, packetData, "TLS_Header", packetID, "tls_version", "handshake_type", "ContentType");
                    break;
            }

        } catch (SQLException e) {
            e.printStackTrace();
        }

        return packetData;
    }

    private static void retrieveFields(Connection conn, Map<String, Object> map, String table, long packetID, String... fields) {
        StringBuilder query = new StringBuilder("SELECT ");
        for (int i = 0; i < fields.length; i++) {
            query.append(fields[i]);
            if (i != fields.length - 1) query.append(", ");
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
        try (Connection conn = DBConnection.getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery("SELECT MAX(PacketID) AS maxID FROM Packet_Metadata")) {
            if (rs.next()) {
                return rs.getLong("maxID");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return -1;
    }
}
