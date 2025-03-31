package com.network.security.packetTesters;

import org.pcap4j.core.*;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.EthernetPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.util.NifSelector;
import java.sql.*;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

public class MTQueuePS {
    private static final String DB_URL = "jdbc:mysql://localhost:3306/nids";
    private static final String USER = "root";
    private static final String PASSWORD = "Maria@mysql05";
    
    private static final int QUEUE_CAPACITY = 200;
    private static final BlockingQueue<Packet> packetQueue = new LinkedBlockingQueue<>(QUEUE_CAPACITY);
    private static final int THREAD_POOL_SIZE = 4; // Number of concurrent threads
    private static final int BATCH_SIZE = 10; // Number of packets per DB insert
    private static final int MAX_PACKETS = 100; // Capture limit
    
    public static void main(String[] args) {
        ExecutorService executor = Executors.newFixedThreadPool(THREAD_POOL_SIZE);
        List<Future<?>> consumerTasks = new ArrayList<>();

        try {
            System.out.println("[DEBUG] Fetching available network interfaces...");
            PcapNetworkInterface device = getDevice();
            if (device == null) {
                System.out.println("[ERROR] No network interfaces found.");
                return;
            }
            System.out.println("[INFO] Selected Interface: " + device.getName());

            // Initialize packet capture
            int snapshotLength = 65536;
            int readTimeout = 50;
            PcapHandle handle = device.openLive(snapshotLength, PromiscuousMode.PROMISCUOUS, readTimeout);
            System.out.println("[INFO] Listening for packets...");

            
            // Start Consumer Thread
            for (int i = 0; i < THREAD_POOL_SIZE; i++) {
                Future<?> task = executor.submit(new PacketConsumer());
                consumerTasks.add(task);
            }
            
            // Capture packets
            PacketListener listener = packet -> {
                try {
                    // Adds them to the packetQueue
                    packetQueue.put(packet);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    System.err.println("[ERROR] Failed to queue packet: " + e.getMessage());
                }
            };

            try {
                handle.loop(MAX_PACKETS, listener);
            } catch (InterruptedException e) {
                System.err.println("[ERROR] Packet capture interrupted: " + e.getMessage());
            } catch (PcapNativeException | NotOpenException e) {
                System.err.println("[ERROR] Pcap handle error: " + e.getMessage());
            } finally {
                handle.close();
            }

            // Allow consumers to finish processing
            Thread.sleep(3000);
            // Shutdown Consumers
            executor.shutdown();
            executor.awaitTermination(5, TimeUnit.SECONDS);

        } catch (Exception e) {
            System.err.println("[ERROR] Exception in main: " + e.getMessage());
        }
    }

    static PcapNetworkInterface getDevice() {
        try {
            System.out.println("[DEBUG] Selecting network interface...");
            return new NifSelector().selectNetworkInterface();
        } catch (IOException e) {
            System.err.println("[ERROR] Failed to get network interface: " + e.getMessage());
            return null;
        }
    }

    static class PacketConsumer implements Runnable {
        @Override
        public void run() {
            try (Connection conn = DriverManager.getConnection(DB_URL, USER, PASSWORD)) {
                System.out.println("[INFO] Database connection successful.");

                List<Packet> batch = new ArrayList<>();

                while (true) {
                    Packet packet = packetQueue.poll(3, TimeUnit.SECONDS); // Wait for packets
                    if (packet != null) {
                        batch.add(packet);
                    }
                    
                    if (batch.size() >= BATCH_SIZE || (packet == null && !batch.isEmpty())) {
                        insertBatch(batch, conn);
                        batch.clear();
                    }
                    
                    if (packet == null && packetQueue.isEmpty()) {
                        System.out.println("[INFO] No more packets. Consumer thread stopping.");
                        break; // Stop when no more packets
                    }
                }
            } catch (SQLException e) {
                System.err.println("[ERROR] Database connection failed: " + e.getMessage());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                System.err.println("[ERROR] Consumer thread interrupted.");
            }
        }
    }

    static void insertBatch(List<Packet> batch, Connection conn) {
        if (batch.isEmpty()) return;

        String insertQuery = "INSERT INTO PACKETS (TIMESTAMP, SRC_IP, DEST_IP, TOTAL_LENGTH, TTL, FLAGS, FRAGMENT_OFFSET, PAYLOAD, SRC_MAC, DEST_MAC, PROTOCOL_NAME) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

        try (PreparedStatement stmt = conn.prepareStatement(insertQuery)) {

            for (Packet packet : batch) {
                if (!packet.contains(IpV4Packet.class)) continue;

                EthernetPacket ethernetPacket = packet.get(EthernetPacket.class);
                IpV4Packet ipv4Packet = packet.get(IpV4Packet.class);
                IpV4Packet.IpV4Header ipHeader = ipv4Packet.getHeader();

                System.out.println("[DEBUG] Processing IPv4 Packet: " + ipHeader.getSrcAddr() + " -> " + ipHeader.getDstAddr());
                
                String srcMac = (ethernetPacket != null) ? ethernetPacket.getHeader().getSrcAddr().toString() : "UNKNOWN";
                String destMac = (ethernetPacket != null) ? ethernetPacket.getHeader().getDstAddr().toString() : "UNKNOWN";
                
                String flags = Integer.toBinaryString(ipHeader.getReservedFlag() ? 1 : 0) +
                                Integer.toBinaryString(ipHeader.getDontFragmentFlag() ? 1 : 0) +
                                Integer.toBinaryString(ipHeader.getMoreFragmentFlag() ? 1 : 0);
                String payload = (ipv4Packet.getPayload() != null) ? ipv4Packet.getPayload().toString() : "";

                stmt.setString(1, ipHeader.getSrcAddr().toString());  // SRC_IP
                stmt.setString(2, ipHeader.getDstAddr().toString()); // DEST_IP
                stmt.setString(3, String.valueOf(ipHeader.getProtocol().value())); // PROTOCOL_ID
                stmt.setString(4, String.valueOf(ipHeader.getTotalLengthAsInt())); // TOTAL_LENGTH
                stmt.setString(5, String.valueOf(ipHeader.getTtlAsInt())); // TTL
                stmt.setString(6, flags); // FLAGS
                stmt.setString(7, String.valueOf(ipHeader.getFragmentOffset())); // FRAGMENT_OFFSET
                stmt.setString(9, payload); // PAYLOAD
                stmt.setString(9, srcMac); // SRC_MAC (Requires correct extraction)
                stmt.setString(10, destMac); // DEST_MAC (Requires correct extraction)
                stmt.setString(11, ipHeader.getProtocol().name()); // PROTOCOL_NAME

                stmt.addBatch();
            }

            int[] rowsInserted = stmt.executeBatch();
            System.out.println("[INFO] Batch Inserted: " + rowsInserted.length + " packets.");
            
        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to insert packet: " + e.getMessage());
        }
    }


}