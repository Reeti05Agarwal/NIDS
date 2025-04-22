package com.network.security.Dao;

import java.sql.Connection; 
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.Map;
import com.network.security.util.DBConnection;

public class PacketDao{
   
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

        Connection conn = null;
        try {
            conn = DBConnection.getConnection();
            conn.setAutoCommit(false);  // Disable auto-commit

            // Insert into Packet_Metadata
            String insertQuery_Packet_Metadata = "INSERT INTO Packet_Metadata (timestamp, payloadsize) VALUES (?, ?)"; 
            try (PreparedStatement stmt = conn.prepareStatement(insertQuery_Packet_Metadata, Statement.RETURN_GENERATED_KEYS)) {
                Timestamp timestamp = (data.get("TIMESTAMP") instanceof java.sql.Timestamp) ? (java.sql.Timestamp) data.get("TIMESTAMP") : new Timestamp(System.currentTimeMillis());
                stmt.setTimestamp(1, timestamp);
                stmt.setInt(2, (Integer) data.get("PACKET_SIZE"));
                stmt.executeUpdate();
                
                ResultSet rs = stmt.getGeneratedKeys();
                long packetID = -1;
                if (rs.next()) {
                    packetID = rs.getLong(1);
                    
                    // Data Link Layer
                    insertLayer(conn, "INSERT INTO Data_Link_Layer (PacketID, srcMAC, destMAC, TYPE) VALUES (?, ?, ?, ?)", packetID, data.get("SRC_MAC"), data.get("DEST_MAC"), data.get("TYPE"));
                    String type = (String) data.get("TYPE");
                    switch (type) {
                        case "WIFI":
                            insertLayer(conn, "INSERT INTO WiFi_Header (PacketID, FRAME_CONTROL, BSSID, SEQ_CONTROL) VALUES (?, ?, ?, ?)",
                            packetID, data.get("WIFI_FRAME_CONTROL"), data.get("BSSID"), data.get("SEQ_CONTROL"));
                    }
                    insertLayer(conn, "INSERT INTO Ethernet_Header (PacketID, ETH_TYPE) VALUES (?, ?)", packetID, data.get("ETH_TYPE")); 

                    // Network Layer
                    insertLayer(conn, "INSERT INTO Network_Layer (PacketID, srcIP, destIP) VALUES (?, ?, ?)", packetID, data.get("SRC_IP"), data.get("DEST_IP"));
                    int ethType = ((Short) data.get("ETH_TYPE")) & 0xFFFF;
                    switch (ethType) {
                        case 0x0800:
                            insertLayer(conn, "INSERT INTO IPv4_Header (PacketID, IP_VERSION, IP_FLAGS, TTL, CHECKSUM, PROTOCOL, FragmentOffset) VALUES (?, ?, ?, ?, ?, ?, ?)",
                            packetID, data.get("IP_VERSION"), data.get("IP_FLAGS"), data.get("TTL"), data.get("IP_CHECKSUM"), data.get("PROTOCOL"), data.get("FRAGMENT_OFFSET"));
                            break;
                        case 0x0806:
                            insertLayer(conn, "INSERT INTO ARP_Header (PacketID, HTYPE, PTYPE, HLEN, PLEN, OPER, ARP_OPERATION) VALUES (?, ?, ?, ?, ?, ?, ?)",
                            packetID, data.get("HTYPE"), data.get("PTYPE"), data.get("HLEN"), data.get("PLEN"), data.get("OPER"), data.get("ARP_OPERATION"));
                            break;
                        case 0x86DD:
                            insertLayer(conn, "INSERT INTO IPv6_Header (PacketID, IP_VERSION, TRAFFIC_CLASS, HOP_LIMIT, FLOW_LABEL, EXTENSIONHEADERS) VALUES (?, ?, ?, ?, ?, ?)",
                            packetID, data.get("IP_VERSION"), data.get("TRAFFIC_CLASS"), data.get("HOP_LIMIT"), data.get("FLOW_LABEL"), data.get("EXTENSION_HEADERS"));
                            break;
                    }

                    // Transport Layer
                    if (data.get("SRC_MAC") != null) {
                        insertLayer(conn, "INSERT INTO Transport_Layer (PacketID, srcPort, destPort) VALUES (?, ?, ?)",
                        packetID, data.get("SRC_PORT"), data.get("DEST_PORT"));
                        switch (data.get("PROTOCOL").toString()) {
                            case "TCP":
                                insertLayer(conn, "INSERT INTO TCP_Header (PacketID, SequenceNum, AckNum, WindowsSize, FLAGS, CHECKSUM, PAYLOAD) VALUES (?, ?, ?, ?, ?, ?, ?)",
                                    packetID, data.get("SEQUENCE_NUM"), data.get("ACK_NUM"), data.get("WINDOW_SIZE"), data.get("TCP_FLAGS"), data.get("TCP_CHECKSUM"), data.get("TCP_PAYLOAD"));
                                break;
                            case "UDP":
                                insertLayer(conn, "INSERT INTO UDP_Header (PacketID, CHECKSUM) VALUES (?, ?)",
                                    packetID, data.get("UDP_CHECKSUM"));
                                break;
                            case "ICMP":
                                insertLayer(conn, "INSERT INTO ICMP_Header (PacketID, TYPE, CODE, CHECKSUM, SEQUENCE_NUM) VALUES (?, ?, ?, ?, ?)",
                                    packetID, data.get("ICMP_TYPE"), data.get("ICMP_CODE"), data.get("CHECKSUM"), data.get("SEQUENCE_NUM"));
                                break;
                        }
                    }
                        
                    

                    // Application Layer
                    insertLayer(conn, "INSERT INTO Application_Layer (PacketID, App_Protocol) VALUES (?, ?)", packetID, data.get("App_Protocol"));
                    String App_Protocol = (String) data.get("App_Protocol");
                    if (App_Protocol !=null){
                        switch (App_Protocol) {
                            case "HTTP":
                                insertLayer(conn, "INSERT INTO HTTP_Header (PacketID, HTTP_METHOD, HOST, user_agent, Auth, ContentType) VALUES (?, ?, ?, ?, ?, ?)",
                                packetID, data.get("HTTP_METHOD"), data.get("HOST"), data.get("USER_AGENT"), data.get("AUTH"), data.get("CONTENT_TYPE"));
                                break;
                            case "HTTPS":
                                insertLayer(conn, "INSERT INTO DNS_Header (PacketID, query_type, response_code, TransactionID, Flags, Question) VALUES (?, ?, ?, ?, ?, ?)",
                                packetID, data.get("QUERY_TYPE"), data.get("RESPONSE_CODE"), data.get("TRANSACTION_ID"), data.get("FLAGS"), data.get("QUESTION"));
                                break;
                            case "DNS":
                                insertLayer(conn, "INSERT INTO TLS_Header (PacketID, tls_version, handshake_type, ContentType) VALUES (?, ?, ?, ?)",
                                packetID, data.get("TLS_VERSION"), data.get("HANDSHAKE_TYPE"), data.get("CONTENT_TYPE"));
                                break;
                        }
                    }
                    
                }
            }

            conn.commit();  // Commit the transaction

        } catch (SQLException e) {
            if (conn != null) {
                try {
                    conn.rollback();  // Rollback the transaction in case of an error
                } catch (SQLException ex) {
                    ex.printStackTrace();
                }
            }
            e.printStackTrace();
            System.err.println("[ERROR] SQL Exception: " + e.getMessage());
            throw new RuntimeException("Database error occurred", e); 
        } finally {
            if (conn != null) {
                try {
                    conn.setAutoCommit(true);  // Restore auto-commit behavior
                } catch (SQLException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}
