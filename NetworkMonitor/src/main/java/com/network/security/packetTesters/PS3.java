package com.network.security.packetTesters;

import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.*;
import org.pcap4j.util.NifSelector;

import java.io.IOException;
import java.sql.*;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

public class PS3 {
    private static final String DB_URL = "jdbc:mysql://localhost:3306/nids";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "Maria@mysql05";

    public static void main(String[] args) {
        try {
            PcapNetworkInterface device = null;
            while (device == null) {
                System.out.println("[ERROR] No network interface found. Try again.");
                device = getDevice();
            }
            
            System.out.println("[INFO] Selected Interface: " + device.getName());

            int snapshotLength = 65536;
            int readTimeout = 50;
            final PcapHandle handle = device.openLive(snapshotLength, PromiscuousMode.PROMISCUOUS, readTimeout);
            System.out.println("[INFO] Listening for packets...");

            PacketListener listener = new PacketListener() {
                @Override
                public void gotPacket(Packet packet) {
                    System.out.println("[DEBUG] Packet received...");
                    processPacket(packet, new Timestamp(System.currentTimeMillis()));
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

    static void processPacket(Packet packet, Timestamp timestamp) {
        System.out.println("[DEBUG] Packet received. Class: " + packet.getClass().getSimpleName());

    if (packet.contains(IpV4Packet.class)) {
        System.out.println("[DEBUG] IPv4 Packet Detected");
        processIpV4Packet(packet, timestamp);
    } else if (packet.contains(EthernetPacket.class)) {
        System.out.println("[DEBUG] Ethernet Packet Detected");
        processEthernetPacket(packet, timestamp);
    } else if (packet.contains(TcpPacket.class)) {
        System.out.println("[DEBUG] TCP Packet Detected");
    } else if (packet.contains(UdpPacket.class)) {
        System.out.println("[DEBUG] UDP Packet Detected");
    } else if (packet.contains(org.pcap4j.packet.ArpPacket.class)) {
        System.out.println("[DEBUG] ARP Packet Detected");
    } else if (packet.contains(org.pcap4j.packet.IpV6Packet.class)) {
        System.out.println("[DEBUG] IPv6 Packet Detected");
    } else if (packet.contains(org.pcap4j.packet.IcmpV4CommonPacket.class)) {
        System.out.println("[DEBUG] ICMP Packet Detected");
    } else {
        // Print raw data for analysis
        byte[] rawData = packet.getRawData();
        if (rawData != null) {
            String hexString = bytesToHex(rawData);
            System.out.println("[DEBUG] Packet: " + hexString);
        } else {
            System.out.println("[ERROR] No raw data found in the packet.");
        }
    }
    }

    static void processIpV4Packet(Packet packet, Timestamp timestamp) {
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            String insertQuery = "INSERT INTO PACKETS (TIMESTAMP, SRC_IP, DEST_IP, PROTOCOL_ID, TOTAL_LENGTH, TTL, FLAGS, FRAGMENT_OFFSET, PAYLOAD, SRC_MAC, DEST_MAC) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
            PreparedStatement stmt = conn.prepareStatement(insertQuery);

            IpV4Packet ipv4Packet = packet.get(IpV4Packet.class);
            EthernetPacket ethernetPacket = packet.get(EthernetPacket.class);

            if (ipv4Packet != null) {
                IpV4Packet.IpV4Header ipHeader = ipv4Packet.getHeader();

                System.out.println("[DEBUG] Processing IPv4 Packet: " + ipHeader.getSrcAddr() + " -> " + ipHeader.getDstAddr());

                stmt.setTimestamp(1, timestamp);
                stmt.setString(2, ipHeader.getSrcAddr().toString());
                stmt.setString(3, ipHeader.getDstAddr().toString());
                stmt.setString(4, String.valueOf(ipHeader.getProtocol().value()));
                stmt.setString(5, String.valueOf(ipHeader.getTotalLengthAsInt()));
                stmt.setString(6, String.valueOf(ipHeader.getTtlAsInt()));
                stmt.setString(7, Integer.toBinaryString(ipHeader.getReservedFlag() ? 1 : 0) +
                        Integer.toBinaryString(ipHeader.getDontFragmentFlag() ? 1 : 0) +
                        Integer.toBinaryString(ipHeader.getMoreFragmentFlag() ? 1 : 0));
                stmt.setString(8, String.valueOf(ipHeader.getFragmentOffset()));
                stmt.setString(9, (ipv4Packet.getPayload() != null) ? ipv4Packet.getPayload().toString() : "");
            }

            if (ethernetPacket != null) {
                EthernetPacket.EthernetHeader ethHeader = ethernetPacket.getHeader();
                stmt.setString(10, ethHeader.getSrcAddr().toString());
                stmt.setString(11, ethHeader.getDstAddr().toString());
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

    static void processEthernetPacket(Packet packet, Timestamp timestamp) {
        EthernetPacket ethernetPacket = packet.get(EthernetPacket.class);
        if (ethernetPacket != null) {
            EthernetPacket.EthernetHeader ethHeader = ethernetPacket.getHeader();
            System.out.println("[DEBUG] Ethernet Packet: " + ethHeader.getSrcAddr() + " -> " + ethHeader.getDstAddr());
        }
    }

    static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02x ", b));
        }
        return hexString.toString().trim(); // Trim to remove trailing space
    }
}
