package com.network.security.packetTesters;

// Represents a network interface
import org.pcap4j.core.*; // Provides functions to capture and process packets
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet; //represents a packet
import org.pcap4j.util.NifSelector; // Selects a network interface

import java.io.IOException;
import java.sql.*; // Provides functions to interact with MySQL database
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
// import org.pcap4j.packet.namednumber.IpNumber;


public class PacketSnifferDetail {
    private static final String DB_URL = "jdbc:mysql://localhost:3306/nids";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "Maria@mysql05";

    public static void main(String[] args) {
        try {
            // Select Network Interface
            System.out.println("[DEBUG] Fetching available network interfaces...");
            PcapNetworkInterface device = getDevice();
            if (device == null) {
                System.out.println("[ERROR] No network interfaces found.");
                return;
            }
            
            System.out.println("[INFO] Selected Interface: " + device.getName());
            System.out.println("Selected Interface: " + (device != null ? device.getName() : "None"));

            // Packet Listner
            int snapshotLength = 65536; // in bytes   
            int readTimeout = 50; // in milliseconds 
            final PcapHandle handle;
            handle = device.openLive(snapshotLength, PromiscuousMode.PROMISCUOUS, readTimeout);
            System.out.println("[INFO] Listening for packets...");
            
            // PacketListener is much more structred than a simple handle.loop
            PacketListener listener = new PacketListener() {
                @Override
                public void gotPacket(Packet packet) {
                    System.out.println("[DEBUG] Packet received...");
                    processPacket(packet, handle.getTimestamp());
                }
            };
            
            int maxPackets = 50;
            handle.loop(maxPackets, listener);
            handle.close();

        } catch (Exception e) {
            System.err.println("[ERROR] Exception in main: " + e.getMessage());
            e.printStackTrace();
        }
    }

    
    static PcapNetworkInterface getDevice() {
        /*
         * Network Interface Function
         * NifSelector().selectNetworkInterface(): Opens a selection prompt for the user
         */
        PcapNetworkInterface device = null;
        try {
            System.out.println("[DEBUG] Selecting network interface...");
            device = new NifSelector().selectNetworkInterface();
        } catch (IOException e) {
            System.err.println("[ERROR] Failed to get network interface: " + e.getMessage());
            e.printStackTrace();
        }
        return device;
    }

    static void processPacket(Packet packet, java.sql.Timestamp timestamp) {
        /*
         * Store Packets in MYSQL Function
         */
        if (!packet.contains(IpV4Packet.class) 
            && !packet.contains(EthernetPacket.class) 
            && !packet.contains(TcpPacket.class) 
            && !packet.contains(UdpPacket.class)) {
        System.out.println("[DEBUG] Ignoring non-IP/Ethernet/TCP/UDP packet: " + packet.getRawData());
        return;
        }

        // Connecting with MYSQL and Insertinng
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            String insertQuery = "INSERT INTO PACKETS (TIMESTAMP, SRC_IP, DEST_IP, PROTOCOL_ID, TOTAL_LENGTH, TTL, FLAGS, FRAGMENT_OFFSET, PAYLOAD, SRC_MAC, DEST_MAC) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
            PreparedStatement stmt = conn.prepareStatement(insertQuery);

            IpV4Packet ipv4Packet = packet.get(IpV4Packet.class);
            EthernetPacket ethernetPacket = packet.get(EthernetPacket.class);

            if (ipv4Packet != null) {
                IpV4Packet.IpV4Header ipHeader = ipv4Packet.getHeader();

                System.out.println("[DEBUG] Processing IPv4 Packet: " + ipHeader.getSrcAddr() + " -> " + ipHeader.getDstAddr());

                String srcIP = ipHeader.getSrcAddr().toString();
                String destIP = ipHeader.getDstAddr().toString();
                String protocolID = String.valueOf(ipHeader.getProtocol().value());
                String totalLength = String.valueOf(ipHeader.getTotalLengthAsInt());
                String ttl = String.valueOf(ipHeader.getTtlAsInt());
                String flags = Integer.toBinaryString(ipHeader.getReservedFlag() ? 1 : 0) +
                               Integer.toBinaryString(ipHeader.getDontFragmentFlag() ? 1 : 0) +
                               Integer.toBinaryString(ipHeader.getMoreFragmentFlag() ? 1 : 0);
                String fragmentOffset = String.valueOf(ipHeader.getFragmentOffset());
                // String checksum = Integer.toHexString(ipHeader.getChecksum()); // Method does not exist
                String payload = (ipv4Packet.getPayload() != null) ? ipv4Packet.getPayload().toString() : "";

                stmt.setString(1, srcIP);  // SRC_IP
                stmt.setString(2, destIP); // DEST_IP
                stmt.setString(3, protocolID); // PROTOCOL_ID
                stmt.setString(4, totalLength); // TOTAL_LENGTH
                stmt.setString(5, ttl); // TTL
                stmt.setString(6, flags); // FLAGS
                stmt.setString(7, fragmentOffset); // FRAGMENT_OFFSET
                stmt.setString(9, payload); // PAYLOAD
            }

            if (ethernetPacket != null) {
                EthernetPacket.EthernetHeader ethHeader = ethernetPacket.getHeader();
                System.out.println("[DEBUG] Ethernet Packet: " + ethHeader.getSrcAddr() + " -> " + ethHeader.getDstAddr());
                stmt.setString(11, ethHeader.getSrcAddr().toString());
                stmt.setString(12, ethHeader.getDstAddr().toString());
            }

            int rowsInserted = stmt.executeUpdate();
            if (rowsInserted > 0) {
                System.out.println("[INFO] Packet inserted successfully.");
            }
            
        } catch (SQLException e) {
            System.err.println("[ERROR] Database Error: " + e.getMessage());
            e.printStackTrace();
        }
    }


}
