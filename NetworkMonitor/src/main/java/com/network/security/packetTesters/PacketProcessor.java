package com.network.security.packetTesters;

import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
//import org.pcap4j.packet.TcpPacket;
//import org.pcap4j.packet.UdpPacket;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.namednumber.IpNumber;
import java.sql.*;

public class PacketProcessor {

    private static final String DB_URL = "jdbc:mysql://localhost:3306/nids";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "Maria@mysql05";

    public static void processPacket(Packet packet, Timestamp timestamp) {
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {

            // Extract Ethernet layer
            EthernetPacket ethernetPacket = packet.get(EthernetPacket.class);
            if (ethernetPacket == null) return;

            String srcMac = ethernetPacket.getHeader().getSrcAddr().toString();
            String destMac = ethernetPacket.getHeader().getDstAddr().toString();

            // Extract IP layer
            IpV4Packet ipPacket = packet.get(IpV4Packet.class);
            if (ipPacket == null) return;

            String srcIp = ipPacket.getHeader().getSrcAddr().getHostAddress();
            String destIp = ipPacket.getHeader().getDstAddr().getHostAddress();
            int totalLength = ipPacket.getHeader().getTotalLengthAsInt();
            int ttl = ipPacket.getHeader().getTtlAsInt();
            String flags = (ipPacket.getHeader().getMoreFragmentFlag() ? "MF " : "") +
                           (ipPacket.getHeader().getDontFragmentFlag() ? "DF " : "") +
                           (ipPacket.getHeader().getReservedFlag() ? "R " : "").trim();
            int fragmentOffset = ipPacket.getHeader().getFragmentOffset();
            String checksum = Integer.toHexString(ipPacket.getHeader().getHeaderChecksum());

            // Extract Protocol
            IpNumber protocol = ipPacket.getHeader().getProtocol();
            int protocolId = getProtocolId(conn, protocol.toString());

            // Extract Payload
            String payload = packet.getRawData().length > 0 ? bytesToHex(packet.getRawData()) : null;

            // Insert packet data into MySQL
            String sql = "INSERT INTO PACKETS (TIMESTAMP, SRC_IP, DEST_IP, PROTOCOL_ID, TOTAL_LENGTH, TTL, FLAGS, " +
                         "FRAGMENT_OFFSET, CHECKSUM, PAYLOAD, SRC_MAC, DEST_MAC) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
            try (PreparedStatement stmt = conn.prepareStatement(sql)) {
                stmt.setTimestamp(1, timestamp);
                stmt.setString(2, srcIp);
                stmt.setString(3, destIp);
                stmt.setInt(4, protocolId);
                stmt.setInt(5, totalLength);
                stmt.setInt(6, ttl);
                stmt.setString(7, flags);
                stmt.setInt(8, fragmentOffset);
                stmt.setString(9, checksum);
                stmt.setString(10, payload);
                stmt.setString(11, srcMac);
                stmt.setString(12, destMac);
                stmt.executeUpdate();
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    private static int getProtocolId(Connection conn, String protocolName) throws SQLException {
        String query = "SELECT PROTOCOL_ID FROM protocols WHERE PROTOCOL_NAME = ?";
        try (PreparedStatement stmt = conn.prepareStatement(query)) {
            stmt.setString(1, protocolName);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) return rs.getInt("PROTOCOL_ID");
        }

        // If protocol not found, insert it
        String insert = "INSERT INTO protocols (PROTOCOL_NAME, DESCRIPTION) VALUES (?, ?)";
        try (PreparedStatement stmt = conn.prepareStatement(insert, Statement.RETURN_GENERATED_KEYS)) {
            stmt.setString(1, protocolName);
            stmt.setString(2, "Detected protocol");
            stmt.executeUpdate();
            ResultSet rs = stmt.getGeneratedKeys();
            if (rs.next()) return rs.getInt(1);
        }
        return -1;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b));
        }
        return sb.toString().trim();
    }
}
