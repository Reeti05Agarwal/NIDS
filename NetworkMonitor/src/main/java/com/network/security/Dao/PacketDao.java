package com.network.security.Dao;
 
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.sql.SQLException;
import java.util.Map;
import com.network.security.util.MYSQLconnection;

public class PacketDao {
     

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

        try (Connection conn = MYSQLconnection.getConnection()) {
            // Insert into Packet_Metadata
            String insertQuery_Packet_Metadata = "INSERT INTO Packet_Metadata (timestamp, payloadsize) VALUES (?, ?)"; 
            try (PreparedStatement stmt = conn.prepareStatement(insertQuery_Packet_Metadata, Statement.RETURN_GENERATED_KEYS)) {
                stmt.setTimestamp(1, (data.get("TIMESTAMP") instanceof java.sql.Timestamp) ? (java.sql.Timestamp) data.get("TIMESTAMP") : null);
                stmt.setInt(2, (Integer) data.get("PACKET_SIZE"));
                stmt.executeUpdate();
                ResultSet rs = stmt.getGeneratedKeys();
                long packetID = -1;
                if (rs.next()) {
                    packetID = rs.getLong(1);

                    // Data Link Layer - Common fields
                    if (data.get("SRC_MAC") != null || data.get("DEST_MAC") != null) {
                        insertLayer(conn, "INSERT INTO Data_Link_Layer (PacketID, srcMAC, destMAC) VALUES (?, ?, ?)", 
                            packetID, data.get("SRC_MAC"), data.get("DEST_MAC"));
                    }

                    // Data Link Layer - Protocol specific headers
                    String dataLinkType = determineDataLinkType(data);
                    switch (dataLinkType) {
                        case "ETHERNET":
                            if (data.get("ETH_TYPE") != null) {
                                insertLayer(conn, "INSERT INTO Ethernet_Header (PacketID, ETH_TYPE) VALUES (?, ?)", 
                                    packetID, data.get("ETH_TYPE"));
                            }
                            break;
                        case "WIFI":
                            if (data.containsKey("WIFI_FRAME_CONTROL") || data.containsKey("BSSID") || data.containsKey("SEQ_CONTROL")) {
                                insertLayer(conn, "INSERT INTO WiFi_Header (PacketID, FRAME_CONTROL, BSSID, SEQ_CONTROL) VALUES (?, ?, ?, ?)",
                                    packetID, data.get("WIFI_FRAME_CONTROL"), data.get("BSSID"), data.get("SEQ_CONTROL"));
                            }
                            break;
                    }

                    // Network Layer - Common fields
                    if (data.get("SRC_IP") != null || data.get("DEST_IP") != null) {
                        insertLayer(conn, "INSERT INTO Network_Layer (PacketID, srcIP, destIP) VALUES (?, ?, ?)", 
                            packetID, data.get("SRC_IP"), data.get("DEST_IP"));
                    }

                    // Network Layer - Protocol specific headers
                    String networkProtocol = determineNetworkProtocol(data);
                    switch (networkProtocol) {
                        case "IPv4":
                            if (isIPv4HeaderPresent(data)) {
                                insertLayer(conn, "INSERT INTO IPv4_Header (PacketID, IP_VERSION, IP_FLAGS, TTL, CHECKSUM, PROTOCOL) VALUES (?, ?, ?, ?, ?, ?)",
                                    packetID, data.get("IP_VERSION"), data.get("IP_FLAGS"), data.get("TTL"), data.get("CHECKSUM"), data.get("PROTOCOL"));
                            }
                            break;
                        case "IPv6":
                            if (isIPv6HeaderPresent(data)) {
                                insertLayer(conn, "INSERT INTO IPv6_Header (PacketID, IP_VERSION, TRAFFIC_CLASS, HOP_LIMIT, FLOW_LABEL, EXTENSIONHEADERS) VALUES (?, ?, ?, ?, ?, ?)",
                                    packetID, data.get("IP_VERSION"), data.get("TRAFFIC_CLASS"), data.get("HOP_LIMIT"), data.get("FLOW_LABEL"), data.get("EXTENSION_HEADERS"));
                            }
                            break;
                        case "ARP":
                            if (isARPHeaderPresent(data)) {
                                insertLayer(conn, "INSERT INTO ARP_Header (PacketID, HTYPE, PTYPE, HLEN, PLEN, OPER, ARP_OPERATION) VALUES (?, ?, ?, ?, ?, ?, ?)",
                                    packetID, data.get("HTYPE"), data.get("PTYPE"), data.get("HLEN"), data.get("PLEN"), data.get("OPER"), data.get("ARP_OPERATION"));
                            }
                            break;
                    }

                    // Transport Layer - Common fields
                    if (data.get("SRC_PORT") != null || data.get("DEST_PORT") != null) {
                        insertLayer(conn, "INSERT INTO Transport_Layer (PacketID, srcPort, destPort) VALUES (?, ?, ?)",
                            packetID, data.get("SRC_PORT"), data.get("DEST_PORT"));
                    }

                    // Transport Layer - Protocol specific headers
                    String transportProtocol = determineTransportProtocol(data);
                    switch (transportProtocol) {
                        case "TCP":
                            if (isTCPHeaderPresent(data)) {
                                insertLayer(conn, "INSERT INTO TCP_Header (PacketID, SequenceNum, AckNum, WindowsSize, FLAGS, CHECKSUM, PAYLOAD, options) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                                    packetID, data.get("SEQUENCE_NUM"), data.get("ACK_NUM"), data.get("WINDOW_SIZE"), data.get("FLAGS"), data.get("CHECKSUM"), data.get("PAYLOAD"), data.get("TCP_OPTIONS"));
                            }
                            break;
                        case "UDP":
                            if (data.get("CHECKSUM") != null) {
                                insertLayer(conn, "INSERT INTO UDP_Header (PacketID, CHECKSUM) VALUES (?, ?)",
                                    packetID, data.get("CHECKSUM"));
                            }
                            break;
                        case "ICMP":
                            if (isICMPHeaderPresent(data)) {
                                insertLayer(conn, "INSERT INTO ICMP_Header (PacketID, TYPE, CODE, CHECKSUM, SEQUENCE_NUM) VALUES (?, ?, ?, ?, ?)",
                                    packetID, data.get("ICMP_TYPE"), data.get("ICMP_CODE"), data.get("CHECKSUM"), data.get("SEQUENCE_NUM"));
                            }
                            break;
                    }

                    // Application Layer
                    String appProtocol = determineAppProtocol(data);
                    if (appProtocol != null && !appProtocol.equals("UNKNOWN")) {
                        insertLayer(conn, "INSERT INTO Application_Layer (PacketID, App_Protocol) VALUES (?, ?)", 
                            packetID, appProtocol);
                        
                        switch (appProtocol) {
                            case "HTTP":
                                if (isHTTPHeaderPresent(data)) {
                                    insertLayer(conn, "INSERT INTO HTTP_Header (PacketID, HTTP_METHOD, HOST, user_agent, Auth, ContentType) VALUES (?, ?, ?, ?, ?, ?)",
                                        packetID, data.get("HTTP_METHOD"), data.get("HOST"), data.get("user_agent"), data.get("Auth"), data.get("ContentType"));
                                }
                                break;
                            case "DNS":
                                if (isDNSHeaderPresent(data)) {
                                    insertLayer(conn, "INSERT INTO DNS_Header (PacketID, query_type, response_code, TransactionID, Flags, Question) VALUES (?, ?, ?, ?, ?, ?)",
                                        packetID, data.get("query_type"), data.get("response_code"), data.get("TransactionID"), data.get("Flags"), data.get("Question"));
                                }
                                break;
                            case "TLS":
                                if (isTLSHeaderPresent(data)) {
                                    insertLayer(conn, "INSERT INTO TLS_Header (PacketID, tls_version, handshake_type, ContentType) VALUES (?, ?, ?, ?)",
                                        packetID, data.get("tls_version"), data.get("handshake_type"), data.get("ContentType"));
                                }
                                break;
                        }
                    }
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // Helper method to determine Data Link type based on available fields
    private static String determineDataLinkType(Map<String, Object> data) {
        // Check for WiFi specific fields
        if (data.containsKey("WIFI_FRAME_CONTROL") || data.containsKey("BSSID") || data.containsKey("SEQ_CONTROL")) {
            return "WIFI";
        } 
        // Check for Ethernet specific fields
        else if (data.containsKey("ETH_TYPE")) {
            return "ETHERNET";
        } 
        // Default to Ethernet if MAC addresses are present but no specific header info
        else if (data.containsKey("SRC_MAC") || data.containsKey("DEST_MAC")) {
            return "ETHERNET";
        } 
        // Cannot determine data link type
        else {
            System.err.println("[WARN] Unable to determine Data Link type. Defaulting to ETHERNET.");
            return "ETHERNET";
        }
    }

    // Helper method to determine Network protocol based on available fields
    private static String determineNetworkProtocol(Map<String, Object> data) {
        // Check IP version if available
        if (data.containsKey("IP_VERSION")) {
            Integer ipVersion = (Integer) data.get("IP_VERSION");
            if (ipVersion != null) {
                if (ipVersion == 4) {
                    return "IPv4";
                } else if (ipVersion == 6) {
                    return "IPv6";
                }
            }
        }
        
        // Check for ARP-specific fields
        if (data.containsKey("HTYPE") || data.containsKey("PTYPE") || data.containsKey("ARP_OPERATION")) {
            return "ARP";
        }
        
        // Try to determine based on other fields
        if (data.containsKey("TTL") || data.containsKey("IP_FLAGS")) {
            return "IPv4";
        } else if (data.containsKey("HOP_LIMIT") || data.containsKey("FLOW_LABEL")) {
            return "IPv6";
        }
        
        // Try to determine from IP address format
        if (data.containsKey("SRC_IP") && data.get("SRC_IP") != null) {
            String srcIp = data.get("SRC_IP").toString();
            if (srcIp.contains(":")) {
                return "IPv6";
            } else if (srcIp.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
                return "IPv4";
            }
        }
        
        if (data.containsKey("DEST_IP") && data.get("DEST_IP") != null) {
            String destIp = data.get("DEST_IP").toString();
            if (destIp.contains(":")) {
                return "IPv6";
            } else if (destIp.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
                return "IPv4";
            }
        }
        
        // Cannot determine network protocol
        System.err.println("[WARN] Unable to determine Network protocol. No network header will be inserted.");
        return "UNKNOWN";
    }

    // Helper method to determine Transport protocol based on available fields
    private static String determineTransportProtocol(Map<String, Object> data) {
        // Check if PROTOCOL field is available
        if (data.containsKey("PROTOCOL") && data.get("PROTOCOL") != null) {
            String protocol = data.get("PROTOCOL").toString();
            if (protocol.equalsIgnoreCase("TCP")) {
                return "TCP";
            } else if (protocol.equalsIgnoreCase("UDP")) {
                return "UDP";
            } else if (protocol.equalsIgnoreCase("ICMP")) {
                return "ICMP";
            }
        }
        
        // Check for protocol-specific fields
        if (data.containsKey("SEQUENCE_NUM") || data.containsKey("ACK_NUM") || data.containsKey("WINDOW_SIZE") || data.containsKey("TCP_OPTIONS")) {
            return "TCP";
        } else if (data.containsKey("ICMP_TYPE") || data.containsKey("ICMP_CODE")) {
            return "ICMP";
        }
        
        // Try to determine from port numbers
        if (data.containsKey("SRC_PORT") || data.containsKey("DEST_PORT")) {
            // If we have port numbers but can't determine protocol, default to TCP as it's more common
            return "TCP";
        }
        
        // Cannot determine transport protocol
        return "UNKNOWN";
    }

    // Helper method to determine Application protocol based on available fields
    private static String determineAppProtocol(Map<String, Object> data) {
        // Check if App_Protocol field is explicitly set
        if (data.containsKey("App_Protocol") && data.get("App_Protocol") != null) {
            return (String) data.get("App_Protocol");
        }
        
        // Try to determine based on port numbers (common ports)
        if (data.containsKey("DEST_PORT")) {
            Integer destPort = (Integer) data.get("DEST_PORT");
            if (destPort != null) {
                switch (destPort) {
                    case 80:
                    case 8080:
                        return "HTTP";
                    case 443:
                        return "TLS";
                    case 53:
                        return "DNS";
                    // Add more common port mappings as needed
                }
            }
        }
        
        // Try to determine from application-specific fields
        if (data.containsKey("HTTP_METHOD") || data.containsKey("HOST") || data.containsKey("user_agent")) {
            return "HTTP";
        } else if (data.containsKey("query_type") || data.containsKey("response_code") || data.containsKey("Question")) {
            return "DNS";
        } else if (data.containsKey("tls_version") || data.containsKey("handshake_type")) {
            return "TLS";
        }
        
        // Cannot determine application protocol
        return "UNKNOWN";
    }

    // Helper methods to check if specific header fields are present

    private static boolean isIPv4HeaderPresent(Map<String, Object> data) {
        return data.containsKey("IP_VERSION") || data.containsKey("IP_FLAGS") || 
               data.containsKey("TTL") || data.containsKey("CHECKSUM") || 
               data.containsKey("PROTOCOL");
    }

    private static boolean isIPv6HeaderPresent(Map<String, Object> data) {
        return data.containsKey("IP_VERSION") || data.containsKey("TRAFFIC_CLASS") || 
               data.containsKey("HOP_LIMIT") || data.containsKey("FLOW_LABEL") || 
               data.containsKey("EXTENSION_HEADERS");
    }

    private static boolean isARPHeaderPresent(Map<String, Object> data) {
        return data.containsKey("HTYPE") || data.containsKey("PTYPE") || 
               data.containsKey("HLEN") || data.containsKey("PLEN") || 
               data.containsKey("OPER") || data.containsKey("ARP_OPERATION");
    }

    private static boolean isTCPHeaderPresent(Map<String, Object> data) {
        return data.containsKey("SEQUENCE_NUM") || data.containsKey("ACK_NUM") || 
               data.containsKey("WINDOW_SIZE") || data.containsKey("FLAGS") || 
               data.containsKey("TCP_OPTIONS");
    }

    private static boolean isICMPHeaderPresent(Map<String, Object> data) {
        return data.containsKey("ICMP_TYPE") || data.containsKey("ICMP_CODE") || 
               data.containsKey("SEQUENCE_NUM");
    }

    private static boolean isHTTPHeaderPresent(Map<String, Object> data) {
        return data.containsKey("HTTP_METHOD") || data.containsKey("HOST") || 
               data.containsKey("user_agent") || data.containsKey("Auth") || 
               data.containsKey("ContentType");
    }

    private static boolean isDNSHeaderPresent(Map<String, Object> data) {
        return data.containsKey("query_type") || data.containsKey("response_code") || 
               data.containsKey("TransactionID") || data.containsKey("Flags") || 
               data.containsKey("Question");
    }

    private static boolean isTLSHeaderPresent(Map<String, Object> data) {
        return data.containsKey("tls_version") || data.containsKey("handshake_type") || 
               data.containsKey("ContentType");
    }
}