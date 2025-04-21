package com.network.security.services;

import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;


import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;

import com.network.security.Dao.PacketDao;
import com.network.security.Dao.PacketRetrieverDao;
import com.network.security.PacketSniffing.PacketParserBuffer;
import com.network.security.PacketSniffing.PacketSnifferService;
//import com.network.security.util.PacketTracker;

import com.network.security.services.Detection.BruteForceService;
import com.network.security.services.Detection.DNSWebFilterService;
import com.network.security.services.Detection.DosService;
import com.network.security.services.Detection.DpiService;
import com.network.security.services.Detection.ExtICMPService;
import com.network.security.services.Detection.SusUserAgentService;
//import com.network.security.services.Detection.InsiderThreatService;
//import com.network.security.services.Detection.MalwareService;


/* 
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
 * 2. InterruptedException Should Be Handled Properly
 * 3. Add error handling.
 * 4. Potential Memory Leak with Threads
 */


public class PacketPipelineService {
    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(PacketPipelineService.class);
    private static final ExecutorService executorService = Executors.newFixedThreadPool(Runtime.getRuntime().availableProcessors());
    private static final BlockingQueue<byte[]> RawPacketQueue = new LinkedBlockingQueue<>(1000);
    private static final BlockingQueue<Map<String, Object>> StoringPacketQueue = new LinkedBlockingQueue<>();
    private static final BlockingQueue<Map<String, Object>> DetectionPacketQueue = new LinkedBlockingQueue<>();

    public static volatile boolean running = true;

    public static void main(String[] args) { 
        PacketSnifferService packetSnifferService = new PacketSnifferService();
        PcapNetworkInterface device = packetSnifferService.getDevice();
        packetSnifferService.DeviceStatus(device);

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            running = false;
            executorService.shutdownNow();
            System.out.println("Shutdown initiated...");
            LOGGER.info("Shutdown initiated...");
        }));

        PacketListener listener = packet -> {
            try {
                System.out.println("[DEBUG] Packet received...");
                LOGGER.info("[DEBUG] Packet received...");
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
 
                LOGGER.error("Error during packet capture: ", e);
            }
        });

        PacketProducer packetproducer = new PacketProducer(RawPacketQueue, StoringPacketQueue);
        PacketConsumer packetconsumer = new PacketConsumer(StoringPacketQueue);
        PacketRetriever retriever = new PacketRetriever(DetectionPacketQueue);
        DetectionDispatcher detector = new DetectionDispatcher(DetectionPacketQueue);

        executorService.submit(packetproducer);  
        executorService.submit(packetconsumer);  
        executorService.submit(retriever);
        executorService.submit(detector);
    }


}

class PacketProducer implements Runnable {
    private BlockingQueue<byte[]> RawPacketQueue;
    private BlockingQueue<Map<String, Object>> StoringPacketQueue;
    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(PacketProducer.class);
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
                
                if (parsedPacketData == null || parsedPacketData.isEmpty()) {
                    System.out.println("[PRODUCER] Skipping null or empty parsed packet");
                    continue;
                }
                
                StoringPacketQueue.put(parsedPacketData); // Add parsed data to the storing queue
                System.out.println("[PRODUCER] Packet parsed and added to StoringPacketQueue: " + parsedPacketData);
                LOGGER.info("[PRODUCER] Packet parsed and added to StoringPacketQueue: " + parsedPacketData);

            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}

class PacketConsumer implements Runnable {
    private BlockingQueue<Map<String, Object>> StoringPacketQueue;
    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(PacketConsumer.class);
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
                
                if (PacketData == null || PacketData.isEmpty()) {
                    System.out.println("[CONSUMER] Empty packet data received, skipping...");
                    continue;
                }

                PacketDao.processPacket(PacketData); // Process the packet data
                System.out.println("[CONSUMER] Packet processed and stored: " + PacketData);
                LOGGER.info("[CONSUMER] Packet processed and stored: " + PacketData);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}

class PacketRetriever implements Runnable {
    private BlockingQueue<Map<String, Object>> detectionQueue;
    PacketRetriever packetRetriever;
    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(PacketRetriever.class);
    

    public PacketRetriever(BlockingQueue<Map<String, Object>> detectionQueue) {
        this.detectionQueue = detectionQueue;
    }

    @Override
    public void run() {
        try {
            while (PacketPipelineService.running) {
                // simulate polling every 5 seconds, or poll only unprocessed packets
                long latestPacketID = PacketRetrieverDao.getLatestPacketID(); // Loading latest packet ID
                Map<String, Object> packetInfo = PacketRetrieverDao.getPacketData(latestPacketID); // Loading packet data
                
                for (Map.Entry<String, Object> packet : packetInfo.entrySet()) {
                    Map<String, Object> singlePacketMap = Map.of(packet.getKey(), packet.getValue());
                    detectionQueue.put(singlePacketMap);
                    System.out.println("[RETRIEVER] Packet fetched from DB and added to DetectionQueue");
                    LOGGER.info("[RETRIEVER] Packet fetched from DB and added to DetectionQueue: " + singlePacketMap);
                }

                sleepWithInterruptCheck(5000);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void sleepWithInterruptCheck(long millis) throws InterruptedException {
        long endTime = System.currentTimeMillis() + millis;
        while (System.currentTimeMillis() < endTime) {
            Thread.sleep(100); // sleep in smaller chunks
            if (!PacketPipelineService.running) break;
        }
    }
    
}

class DetectionDispatcher implements Runnable {
    private BlockingQueue<Map<String, Object>> detectionQueue;
    private ExecutorService detectionServicePool;
    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(DetectionDispatcher.class);
    

    // Inject your detection services
    private final BruteForceService bruteForceService = new BruteForceService();
    private final DNSWebFilterService dnsWebFilterService = new DNSWebFilterService();
    private final DosService dosService = new DosService();
    private final DpiService dpiService = new DpiService();
    private final ExtICMPService extICMPService = new ExtICMPService();
    //private final InsiderThreatService insiderThreatService = new InsiderThreatService();
    //private final MalwareService malwareService = new MalwareService();
    private final SusUserAgentService susUserAgentService = new SusUserAgentService();

    public DetectionDispatcher(BlockingQueue<Map<String, Object>> detectionQueue) {
        this.detectionQueue = detectionQueue;
        this.detectionServicePool = Executors.newFixedThreadPool(5); // 5 detection services in parallel
    }

    @Override
    public void run() {
        try {
            while (PacketPipelineService.running) {
                Map<String, Object> packetData = detectionQueue.take();

                detectionServicePool.submit(() -> bruteForceService.loadBruteForce(packetData));
                detectionServicePool.submit(() -> dnsWebFilterService.loadDnsWebFilterRules(packetData));
                detectionServicePool.submit(() -> dosService.loadDosService(packetData));
                detectionServicePool.submit(() -> dpiService.loadDpiDetectorKeywords(packetData));
                detectionServicePool.submit(() -> extICMPService.loadICMPRules(packetData));
                //detectionServicePool.submit(() -> insiderThreatService.loadInsiderThreat(packetData));
                //detectionServicePool.submit(() -> malwareService.loadMalwareSig(packetData));
                detectionServicePool.submit(() -> susUserAgentService.loadSuspiciousUserAgent(packetData));

                System.out.println("[DETECTOR] Packet sent to detection services: " + packetData);
                LOGGER.info("[DETECTOR] Packet sent to detection services: " + packetData);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}





 