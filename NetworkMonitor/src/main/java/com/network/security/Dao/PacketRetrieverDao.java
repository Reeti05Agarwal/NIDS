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
            retrieveFields(conn, packetData, "Data_Link_Layer", packetID, "srcMAC", "destMAC", "TYPE");


            String type = (String) packetData.get("TYPE");
            retrieveFields(conn, packetData, "Ethernet_Header", packetID, "ETH_TYPE");
            if (type == "WIFI"){
                retrieveFields(conn, packetData, "WiFi_Header", packetID, "FRAME_CONTROL", "BSSID", "SEQ_CONTROL");
            }

            retrieveFields(conn, packetData, "Network_Layer", packetID, "srcIP", "destIP");
            int ethType = ((Short) packetData.get("ETH_TYPE")) & 0xFFFF;
            System.out.println("[RETRIEVER] Eth_Type :" + ethType);
            
            switch (ethType) {
                case 0x0800:
                    retrieveFields(conn, packetData, "IPv4_Header", packetID, "IP_VERSION", "IP_FLAGS", "TTL", "CHECKSUM", "PROTOCOL", "FragmentOffset");
                    break;
                case 0x86DD:
                    retrieveFields(conn, packetData, "IPv6_Header", packetID, "IP_VERSION", "TRAFFIC_CLASS", "HOP_LIMIT", "FLOW_LABEL", "EXTENSIONHEADERS");
                    break;
                case 0x0806:
                    retrieveFields(conn, packetData, "ARP_Header", packetID, "HTYPE", "PTYPE", "HLEN", "PLEN", "OPER", "ARP_OPERATION");
                    break;
                default:
                    System.out.println("Unknown ETH_TYPE: " + ethType);
                    

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
                case "DNS":
                    retrieveFields(conn, packetData, "DNS_Header", packetID, "query_type", "response_code", "TransactionID", "Flags", "Question");
                    break;    
                case "HTTPS":
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
                ResultSetMetaData meta = rs.getMetaData();
                for (String field : fields) {
                    int columnIndex = rs.findColumn(field);
                    int columnType = meta.getColumnType(columnIndex);
    
                    Object value;
    
                    switch (columnType) {
                        case Types.VARCHAR: 
                            value = rs.getString(field);
                            break;
    
                        case Types.INTEGER:
                            value = rs.getInt(field);
                            if (rs.wasNull()) value = null;
                            break;

    
                        case Types.BIGINT:
                            value = rs.getLong(field);
                            if (rs.wasNull()) value = null;
                            break;
    
                        case Types.TIMESTAMP:
                        case Types.TIMESTAMP_WITH_TIMEZONE:
                            value = rs.getTimestamp(field);
                            break;

                        default:
                            value = rs.getObject(field); // fallback for unhandled types
                            break;
                    }
    
                    map.put(field, value);
                }
            }
        } catch (SQLException e) {
            System.err.println("Error retrieving from " + table + ": " + e.getMessage());
        }
    }
    

    
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