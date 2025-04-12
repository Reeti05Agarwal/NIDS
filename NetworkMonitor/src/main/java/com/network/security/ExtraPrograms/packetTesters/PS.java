package com.network.security.ExtraPrograms.packetTesters;

// Represents a network interface
import org.pcap4j.core.*; // Provides functions to capture and process packets
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet; //represents a packet
import org.pcap4j.util.NifSelector; // Selects a network interface
import java.sql.*; // Provides functions to interact with MySQL database

//import java.io.IOException;
import java.util.List;

public class PS {
    private static final String DB_URL = "jdbc:mysql://localhost:3306/nids";
    private static final String USER = "root";
    private static final String PASSWORD = "Maria@mysql05";

    public static void main(String[] args) {
        try {
            // findAllDevs: Retrieves a List all available network interfaces
            List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();
            if (interfaces == null || interfaces.isEmpty()) {
                System.out.println("No network interfaces found.");
                return;
            }
            System.out.println("Available Network Interfaces:");
            for (int i = 0; i < interfaces.size(); i++) {
                System.out.println(i + ": " + interfaces.get(i).getName() + " - " + interfaces.get(i).getDescription());
            }

            // Allow user to select a network interface
            // NifSelector().selectNetworkInterface(): Opens a selection prompt for the user
            PcapNetworkInterface networkInterface = new NifSelector().selectNetworkInterface();
            // print the selected interface
            System.out.println("Selected Interface: " + (networkInterface != null ? networkInterface.getName() : "None"));


            /*
            * Output:
             * Available Network Interfaces:
                0: eth0 - Ethernet Interface
                1: wlan0 - Wi-Fi Adapter
                2: lo - Loopback Interface
                Select a network interface:
             */


            // openLive() : Initializes Packet Capture.
            // It takes 3 inputs: 1. Snapshot length 2. Mode 3. Read timeout
            // It returns PcapHandle object (it represents packet capture session), which is used to opening a network interface, capturing packets, filtering traffic, and closing the session.
            // 65536 bytes buffer size (captures full packet size)
            // PromiscuousMode.PROMISCUOUS: Capture all packets on the network (including packets not addressed to this device)
            // 10: Read timeout in milliseconds
            PcapHandle handle = networkInterface.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);
            System.out.println("Listening for packets...");


            // Capture and process packets (-1: loop indefinitely) using a single thread
            // (Packet packet) -> { ... }: Lambda function to process each packet
            // Each packet is passed as Packet object to the lambda function 
            handle.loop(-1, (Packet packet) -> {
                
                // DriverManager.getConnection(): Establishes a connection to the database
                try (Connection conn = DriverManager.getConnection(DB_URL, USER, PASSWORD)) {
                    System.out.println("Capturing packet...");
                    IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
                    if (ipV4Packet == null) return; // Skip non-IPv4 packets

                    // Extract packet data
                    String srcIP = ipV4Packet.getHeader().getSrcAddr().toString();
                    String destIP = ipV4Packet.getHeader().getDstAddr().toString();

                    System.out.println("Capturing packet...PART 2");

                    // Insert packet data into database
                    String sql = "INSERT INTO packets (SRC_IP, DEST_IP, PAYLOAD) " +
                                 "VALUES (?, ?, ?)";
                    // PreparedStatement: Parameterised SQL Statements (prevents sql injection)
                    PreparedStatement stmt = conn.prepareStatement(sql);
                    stmt.setString(1, srcIP); // SRC_IP
                    stmt.setString(2, destIP); // DEST_IP
                    stmt.setString(9, packet.toString()); // PAYLOAD
                    stmt.executeUpdate(); // Execute SQL query
                    System.out.println("Packet inserted: " + srcIP + " -> " + destIP );

                } catch (Exception e) {
                    // Error handling
                    e.printStackTrace();
                }
            });

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

     
}
