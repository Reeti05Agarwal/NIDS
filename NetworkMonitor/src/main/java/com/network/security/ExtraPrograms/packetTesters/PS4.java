package com.network.security.ExtraPrograms.packetTesters;

// Represents a network interface
import org.pcap4j.core.*; // Provides functions to capture and process packets
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet; //represents a packet
import org.pcap4j.util.NifSelector; // Selects a network interface

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.sql.*; // Provides functions to interact with MySQL database
import java.util.HashMap;
import java.util.Map;

import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;
// import org.pcap4j.packet.namednumber.IpNumber;


public class PS4 {
    private static final String DB_URL = "jdbc:mysql://localhost:3306/nids";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "Maria@mysql05";

    // hashmap to map the protocols 
    private static final Map<Integer, String> PROTOCOL_MAP = new HashMap<>();
    static {
        PROTOCOL_MAP.put(1, "ICMP");
        PROTOCOL_MAP.put(2, "IGMP");
        PROTOCOL_MAP.put(6, "TCP");
        PROTOCOL_MAP.put(17, "UDP");
        PROTOCOL_MAP.put(50, "ESP");
        PROTOCOL_MAP.put(51, "AH");
        PROTOCOL_MAP.put(47, "GRE");
        PROTOCOL_MAP.put(132, "SCTP");
    }

    //System.out.println("  Protocol: " + PROTOCOL_MAP.getOrDefault(protocol, "Unknown (" + protocol + ")"));


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
        // Connecting with MYSQL and Insertinng
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            String insertQuery = "INSERT INTO PACKETS (TIMESTAMP, SRC_IP, DEST_IP, PROTOCOL_ID, TOTAL_LENGTH, TTL, FLAGS, FRAGMENT_OFFSET, PAYLOAD, SRC_MAC, DEST_MAC) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
            PreparedStatement stmt = conn.prepareStatement(insertQuery);

            byte[] rawData = packet.getRawData();
            String hexString = null;
            if (rawData != null) {
                hexString = bytesToHex(rawData);
                System.out.println("[DEBUG] Packet: " + hexString);
            } else {
                System.out.println("[ERROR] No raw data found in the packet.");
            }

            if (hexString != null) {
                parsePacket(rawData);
            }

            /*
            stmt.setString(1, srcIP);  // SRC_IP
            stmt.setString(2, destIP); // DEST_IP
            stmt.setString(1, srcMAC);  // SRC_MAC
            stmt.setString(2, destMAC); // DEST_MAC
            stmt.setString(3, protocolID); // PROTOCOL_ID
            stmt.setString(4, totalLength); // TOTAL_LENGTH
            stmt.setString(5, ttl); // TTL
            stmt.setString(6, flags); // FLAGS
            stmt.setString(7, fragmentOffset); // FRAGMENT_OFFSET
            stmt.setString(9, payload); // PAYLOAD
             */
 

            int rowsInserted = stmt.executeUpdate();
            if (rowsInserted > 0) {
                System.out.println("[INFO] Packet inserted successfully.");
            }
            
        } catch (SQLException e) {
            System.err.println("[ERROR] Database Error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02x ", b));
        }
        return hexString.toString().trim(); // Trim to remove trailing space
    }
    /* 
    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                                 + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }*/

    public static void parsePacket(byte[] packet) {
        //Ensures minimum packet length for valid Ethernet and IP headers (34 bytes).
        if (packet.length < 34) {
            System.out.println("[ERROR] Packet is too short!");
            return;
        }

        // Extract Ethernet MAC addresses
        String srcMac = getMacAddress(packet, 6); //extracts the Source MAC Address (bytes 6-11).
        String destMac = getMacAddress(packet, 0); //extracts the Destination MAC Address (bytes 0-5).
        int ethType = ((packet[12] & 0xFF) << 8) | (packet[13] & 0xFF);
        /*
         * Bytes 12-13 determine the next protocol:
                0x0800 → IPv4
                0x86DD → IPv6
         */

        //Displays MAC addresses and EtherType (in hexadecimal format).
        System.out.println("Ethernet Header:");
        System.out.println("  Source MAC: " + srcMac);
        System.out.println("  Destination MAC: " + destMac);
        System.out.printf("  EtherType: 0x%04X\n", ethType);

        // If it's an IPv4 packet (0x0800)
        if (ethType == 0x0800) {
            parseIPv4Header(packet);
        } else {
            System.out.println("[INFO] Non-IPv4 packet detected.");
        }
    }


    // Parsing IPv4 Header
    private static void parseIPv4Header(byte[] packet) {

        // Extract fields from IPv4 header by using Bitwise Operator & Binary Manipulations

        /*
         * First Byte - packet[14] contains version(4 bites) and IHL(4 bites)
         * packet[14] >> 4, right shift (>> 4) moves the first 4 bites to the right, eliminating IHL part
         * Bitwise AND (& 0xF) isolates the last 4 bits.
         */
        int version = (packet[14] >> 4) & 0xF; //Extracts IP version (IPv4 = 4).
        int ihl = (packet[14] & 0xF) * 4;  // IHL (Internet Header Length)
        int totalLength = ((packet[16] & 0xFF) << 8) | (packet[17] & 0xFF); //Extracts entire packet length.
        int protocol = packet[23] & 0xFF;
        /*
         * 1 -> ICMP
         * 2 -> IGMP
         * 6 → TCP
         * 17 → UDP
         * 47 -> GRE
         * 50 -> ESP
         * 51 -> AH
         * 89 -> OSPF
         * 132 -> SCTP
         */

        String srcIP = getIpAddress(packet, 26); //Bytes 26-29 → Source IP
        String destIP = getIpAddress(packet, 30); //Bytes 30-33 → Destination IP

        System.out.println("\nIPv4 Header:");
        System.out.println("  Version: " + version);
        System.out.println("  Header Length: " + ihl + " bytes");
        System.out.println("  Total Length: " + totalLength + " bytes");
        System.out.println("  Protocol: " + (protocol == 6 ? "TCP" : protocol == 17 ? "UDP" : "Other"));
        System.out.println("  Source IP: " + srcIP);
        System.out.println("  Destination IP: " + destIP);

        // Check if it's UDP or TCP
        if (protocol == 6) {
            parseTcpHeader(packet, ihl);
        } else if (protocol == 17) {
            parseUdpHeader(packet, ihl);
        }
    }

    private static void parseTcpHeader(byte[] packet, int ihl) {
        int srcPort = ((packet[14 + ihl] & 0xFF) << 8) | (packet[15 + ihl] & 0xFF);
        int destPort = ((packet[16 + ihl] & 0xFF) << 8) | (packet[17 + ihl] & 0xFF);

        System.out.println("\nTCP Header:");
        System.out.println("  Source Port: " + srcPort);
        System.out.println("  Destination Port: " + destPort);
    }

    private static void parseUdpHeader(byte[] packet, int ihl) {
        int srcPort = ((packet[14 + ihl] & 0xFF) << 8) | (packet[15 + ihl] & 0xFF);
        int destPort = ((packet[16 + ihl] & 0xFF) << 8) | (packet[17 + ihl] & 0xFF);

        System.out.println("\nUDP Header:");
        System.out.println("  Source Port: " + srcPort);
        System.out.println("  Destination Port: " + destPort);
    }



    private static String getMacAddress(byte[] packet, int start) {
        return String.format("%02X:%02X:%02X:%02X:%02X:%02X",
                packet[start] & 0xFF, packet[start + 1] & 0xFF, packet[start + 2] & 0xFF,
                packet[start + 3] & 0xFF, packet[start + 4] & 0xFF, packet[start + 5] & 0xFF);
    }

    private static String getIpAddress(byte[] packet, int start) {
        try {
            return InetAddress.getByAddress(new byte[]{packet[start], packet[start + 1], packet[start + 2], packet[start + 3]}).getHostAddress();
        } catch (UnknownHostException e) {
            return "Invalid IP";
        }
    }




}
 