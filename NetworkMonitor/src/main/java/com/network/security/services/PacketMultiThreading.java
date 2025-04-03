package com.network.security.services;

// import java.nio.ByteBuffer;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;

import com.network.security.packetTesters.PacketParserMain;

/*
 * Three Thread Running in Parallel
 * 1. Packet Sniffing (PacketSnifferService.java)
 * 2. Packet Parsing (PacketParcerBuffer.java) :  takes packets from the queue and parses them
 * 3. Packet Storing (PacketStoring.java) : takes packets from the queue and processes them (e.g., stores them)
 * 
 * 
 * THINGS TO DO:
 * 1. Gracefull stop of execution
 * 2. InterruptedException Should Be Handled Properly
 * 3. Add error handling.
 * 4. Potential Memory Leak with Threads
 */


public class PacketMultiThreading {
    private static final Logger LOGGER = Logger.getLogger(PacketParserMain.class.getName());
    private static final ExecutorService executorService = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());
    private static final BlockingQueue<byte[]> RawPacketQueue = new LinkedBlockingQueue<>();
    private static final BlockingQueue<Map<String, Object>> StorinPacketQueue = new LinkedBlockingQueue<>();

    public static void main(String[] args) { 
        PacketSnifferService packetSnifferService = new PacketSnifferService();
        
        
        PcapNetworkInterface device = packetSnifferService.getDevice();
        packetSnifferService.DeviceStatus(device);

        PacketListener listener = packet -> {
            try {
                System.out.println("[DEBUG] Packet received...");
                RawPacketQueue.put(packet.getRawData()); // Add raw data to queue
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
             
        };
 
        int snapshotLength = 65536;
        int readTimeout = 50;  
        new Thread(() -> {
            try (PcapHandle handle = device.openLive(snapshotLength, PromiscuousMode.PROMISCUOUS, readTimeout);) {
                handle.loop(-1, listener); // Capture indefinitely
            } catch (PcapNativeException | NotOpenException | InterruptedException e) {
                LOGGER.log(Level.SEVERE, "Error during packet capture: ", e);
            }
        }).start();


        PacketProducer packetproducer = new PacketProducer(RawPacketQueue, StorinPacketQueue);
        PacketConsumer packetconsumer = new PacketConsumer(StorinPacketQueue);
        // Producer : Packet Sniffing
        // PacketSnifferService.java
        // PacketParcerBuffer.java
        Thread producerThread = new Thread(packetproducer); 
        // Consumer : Packet Storing in Mysql
        // PacketStoring.java
        Thread consumerThread = new Thread(packetconsumer);

        producerThread.start();
        consumerThread.start();
    }


}

class PacketProducer implements Runnable {
    private BlockingQueue<byte[]> RawPacketQueue;
    private BlockingQueue<Map<String, Object>> StorinPacketQueue;
    PacketParcerBuffer packetParser = new PacketParcerBuffer();

    public PacketProducer(BlockingQueue<byte[]> RawPacketQueue, BlockingQueue<Map<String, Object>> StorinPacketQueue) {
        this.RawPacketQueue = RawPacketQueue;
        this.StorinPacketQueue = StorinPacketQueue;
    }

    @Override
    public void run() {
        try {
            while (true) {
                byte[] packetData = RawPacketQueue.take(); // Fetch from queue
                Map<String, Object> parsedPacketData = PacketParcerBuffer.parsePacket(packetData); // Parse it in buffer function
                StorinPacketQueue.put(parsedPacketData); // Add parsed data to the storing queue
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}


class PacketConsumer implements Runnable {
    private BlockingQueue<Map<String, Object>> StorinPacketQueue;
    PacketStoring packetStoring = new PacketStoring();

    public PacketConsumer(BlockingQueue<Map<String, Object>> StorinPacketQueue) {
        this.StorinPacketQueue = StorinPacketQueue;
    }

    @Override
    public void run() {
        try {
            while (true) {
                Map<String, Object> PacketData = StorinPacketQueue.take();
                // byte[] packetData = new byte[buffer.remaining()];
                // buffer.get(packetData);
                PacketStoring.processPacket(PacketData); // Process the packet data
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}

 