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

import com.network.security.Dao.PacketDao;
import com.network.security.PacketSniffing.PacketParserBuffer;
import com.network.security.PacketSniffing.PacketSnifferService;
/*
 * 
 * 
 * Three Thread Running in Parallel
 * 1. Packet Sniffing (PacketSnifferService.java)
 * 2. Packet Parsing (PacketParserBuffer.java) :  takes packets from the queue and parses them
 * 3. Packet Storing (PacketStoring.java) : takes packets from the queue and processes them (e.g., stores them)
 * 
 * blocking queue:
 * 1. packetSniffing -> RawPacketQueue (BlockingQueue<byte[]>)
 * 2. packetParserBuffer -> StoringPacketQueue (BlockingQueue<Map<String, Object>>)
 * 
 * THINGS TO DO:
 * 1. Gracefull stop of execution
 * 2. InterruptedException Should Be Handled Properly
 * 3. Add error handling.
 * 4. Potential Memory Leak with Threads
 */


public class PacketPipelineService {
    private static final Logger LOGGER = Logger.getLogger(PacketPipelineService.class.getName());
    private static final ExecutorService executorService = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());
    private static final BlockingQueue<byte[]> RawPacketQueue = new LinkedBlockingQueue<>(1000);
    private static final BlockingQueue<Map<String, Object>> StoringPacketQueue = new LinkedBlockingQueue<>();
    public static volatile boolean running = true;

    public static void main(String[] args) { 
        PacketSnifferService packetSnifferService = new PacketSnifferService();
        PcapNetworkInterface device = packetSnifferService.getDevice();
        packetSnifferService.DeviceStatus(device);

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            running = false;
            executorService.shutdownNow();
            System.out.println("Shutdown initiated...");
        }));

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
        executorService.submit(() -> {
            try (PcapHandle handle = device.openLive(snapshotLength, PromiscuousMode.PROMISCUOUS, readTimeout);) {
                handle.loop(-1, listener); // Capture indefinitely
            } catch (PcapNativeException | NotOpenException | InterruptedException e) {
                LOGGER.log(Level.SEVERE, "Error during packet capture: ", e);
            }
        });

        PacketProducer packetproducer = new PacketProducer(RawPacketQueue, StoringPacketQueue);
        PacketConsumer packetconsumer = new PacketConsumer(StoringPacketQueue);

        executorService.submit(packetproducer); // Submit producer to executor
        executorService.submit(packetconsumer); // Submit consumer to executor
    }


}

class PacketProducer implements Runnable {
    private BlockingQueue<byte[]> RawPacketQueue;
    private BlockingQueue<Map<String, Object>> StoringPacketQueue;
    PacketParserBuffer packetParser = new PacketParserBuffer();

    public PacketProducer(BlockingQueue<byte[]> RawPacketQueue, BlockingQueue<Map<String, Object>> StoringPacketQueue) {
        this.RawPacketQueue = RawPacketQueue;
        this.StoringPacketQueue = StoringPacketQueue;
    }

    @Override
    public void run() {
        try {
            while (PacketPipelineService.running) {
                byte[] packetData = RawPacketQueue.take(); // Fetch from queue
                Map<String, Object> parsedPacketData = PacketParserBuffer.parsePacket(packetData); // Parse it in buffer function
                StoringPacketQueue.put(parsedPacketData); // Add parsed data to the storing queue
                System.out.println("[PRODUCER] Packet parsed and added to StoringPacketQueue: " + parsedPacketData);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}

class PacketConsumer implements Runnable {
    private BlockingQueue<Map<String, Object>> StoringPacketQueue;
    PacketDao packetDao = new PacketDao();
    
    public PacketConsumer(BlockingQueue<Map<String, Object>> StoringPacketQueue) {
        this.StoringPacketQueue = StoringPacketQueue;
    }

    @Override
    public void run() {
        try {
            while (PacketPipelineService.running) {
                System.out.println("[CONSUMER] Waiting for packet to process...");
                Map<String, Object> PacketData = StoringPacketQueue.take();
                PacketDao.processPacket(PacketData); // Process the packet data
                System.out.println("[CONSUMER] Packet processed and stored: " + PacketData);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}

 