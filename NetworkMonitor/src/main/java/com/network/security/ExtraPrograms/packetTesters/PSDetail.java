package com.network.security.ExtraPrograms.packetTesters;

// Imports for packet capturing
import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.*; 
import org.pcap4j.util.NifSelector;

// Imports for database connection
import java.io.IOException;
import java.sql.*;
//import java.util.List;

public class PSDetail {
    private static final String DB_URL = "jdbc:mysql://localhost:3306/nids";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "Maria@mysql05";
    private static final int MAX_PACKETS = 50;

    public static void main(String[] args) {
        try {
            System.out.println("[DEBUG] Fetching available network interfaces...");
            PcapNetworkInterface device = getDevice();
            if (device == null) {
                System.out.println("[ERROR] No network interfaces found.");
                return;
            }
            System.out.println("[INFO] Selected Interface: " + device.getName());

            int snapshotLength = 65536; // Buffer size
            int readTimeout = 50;       // Read timeout in milliseconds
            try (PcapHandle handle = device.openLive(snapshotLength, PromiscuousMode.PROMISCUOUS, readTimeout)) {
                System.out.println("[INFO] Listening for packets...");
                
                PacketListener listener = packet -> {
                    System.out.println("[DEBUG] Packet received...");
                    processPacket(packet, handle.getTimestamp());
                };

                try {
                    handle.loop(MAX_PACKETS, listener);
                } catch (NotOpenException e) {
                    System.err.println("[ERROR] Handle not open: " + e.getMessage());
                    e.printStackTrace();
                }
            }
        } catch (PcapNativeException | InterruptedException e) {
            System.err.println("[ERROR] Pcap error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static PcapNetworkInterface getDevice() {
        try {
            System.out.println("[DEBUG] Selecting network interface...");
            return new NifSelector().selectNetworkInterface();
        } catch (IOException e) {
            System.err.println("[ERROR] Failed to get network interface: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    private static void processPacket(Packet packet, java.sql.Timestamp timestamp) {
        if (!packet.contains(IpV4Packet.class) 
            && !packet.contains(EthernetPacket.class) 
            && !packet.contains(TcpPacket.class) 
            && !packet.contains(UdpPacket.class)) {
            System.out.println("[DEBUG] Ignoring non-IP/Ethernet/TCP/UDP packet.");
            return;
        }

        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             PreparedStatement stmt = conn.prepareStatement(
                     "INSERT INTO PACKETS (TIMESTAMP, SRC_IP, DEST_IP, PROTOCOL_ID, TOTAL_LENGTH, TTL, FLAGS, FRAGMENT_OFFSET, PAYLOAD, SRC_MAC, DEST_MAC) " +
                             "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")) {

            stmt.setTimestamp(1, timestamp);

            IpV4Packet ipv4Packet = packet.get(IpV4Packet.class);
            EthernetPacket ethernetPacket = packet.get(EthernetPacket.class);

            if (ipv4Packet != null) {
                processIPv4Packet(stmt, ipv4Packet);
            }

            if (ethernetPacket != null) {
                processEthernetPacket(stmt, ethernetPacket);
            }

            stmt.addBatch();
            int[] batchResults = stmt.executeBatch();
            System.out.println("[INFO] Inserted " + batchResults.length + " packet(s) into database.");

        } catch (SQLException e) {
            System.err.println("[ERROR] Database Error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void processIPv4Packet(PreparedStatement stmt, IpV4Packet ipv4Packet) throws SQLException {
        IpV4Packet.IpV4Header ipHeader = ipv4Packet.getHeader();
        System.out.println("[DEBUG] Processing IPv4 Packet: " + ipHeader.getSrcAddr() + " -> " + ipHeader.getDstAddr());

        stmt.setString(2, ipHeader.getSrcAddr().toString());
        stmt.setString(3, ipHeader.getDstAddr().toString());
        stmt.setInt(4, ipHeader.getProtocol().value());
        stmt.setInt(5, ipHeader.getTotalLengthAsInt());
        stmt.setInt(6, ipHeader.getTtlAsInt());

        String flags = (ipHeader.getReservedFlag() ? "1" : "0") +
                       (ipHeader.getDontFragmentFlag() ? "1" : "0") +
                       (ipHeader.getMoreFragmentFlag() ? "1" : "0");
        stmt.setString(7, flags);
        stmt.setInt(8, ipHeader.getFragmentOffset());
        stmt.setString(9, ipv4Packet.getPayload() != null ? ipv4Packet.getPayload().toString() : "");
    }

    private static void processEthernetPacket(PreparedStatement stmt, EthernetPacket ethernetPacket) throws SQLException {
        EthernetPacket.EthernetHeader ethHeader = ethernetPacket.getHeader();
        System.out.println("[DEBUG] Ethernet Packet: " + ethHeader.getSrcAddr() + " -> " + ethHeader.getDstAddr());

        stmt.setString(10, ethHeader.getSrcAddr().toString());
        stmt.setString(11, ethHeader.getDstAddr().toString());
    }
}
