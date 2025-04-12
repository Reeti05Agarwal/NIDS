package com.network.security.ExtraPrograms.packetTesters;

import java.net.InetAddress; //Used to convert raw byte IP addresses into human-readable format
import java.net.UnknownHostException; //Handles errors when converting an invalid IP address.

public class PacketParser {
    public static void main(String[] args) {
         
        byte[] packet = {
            -72, 30, -92, -70, -119, 117, 32, 12, -122, -90, 98, 16, 8, 0, // Ethernet
            69, -72, 0, 54, 0, 0, 64, 0, 60, 17, -90, -19, -114, -6, 70, 106, -64, -88, 1, 5, // IPv4
            1, -69, -2, -102, 0, 34, -88, 26, // UDP
            67, -47, 114, 38, -77, -6, -70, 90, 16, 10 // Payload
        };

        /*
         * The packet contains:
                Ethernet header (first 14 bytes).
                IPv4 header (next 20 bytes).
                UDP header (next 8 bytes).
                Payload data (remaining bytes).
         */

        parsePacket(packet);
    }



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
         * 6 → TCP
         * 17 → UDP
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

