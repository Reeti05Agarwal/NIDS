package com.network.security.services;

import java.util.Map;
import java.util.concurrent.BlockingQueue;
//import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;


import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;

import com.network.security.Dao.PacketDao;
import com.network.security.Dao.PacketRetrieverDao;
import com.network.security.Dao.EvaluatedDao;
import com.network.security.PacketSniffing.PacketParserBuffer;
import com.network.security.PacketSniffing.PacketSnifferService;

import com.network.security.services.Detection.BruteForceService;
import com.network.security.services.Detection.DNSWebFilterService;
import com.network.security.services.Detection.DosService;
import com.network.security.services.Detection.DpiService;
import com.network.security.services.Detection.ExtICMPService;
import com.network.security.services.Detection.SusUserAgentService;
 
/*
 * Anonymous Thread (Packet Sniffing)
 * PacketProducer (Decoding)
 * PacketConsumer (Storing)
 * PacketRetriever ()
 * DetectionDispatcher
 * 
 * List of dependibility
 */

public class PacketPipelineService {
    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(PacketPipelineService.class);
    private static final ExecutorService executorService = Executors.newFixedThreadPool(6);
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
                Thread.sleep(100); 
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
                 
            }
        });
        executorService.submit(new PacketProducer(RawPacketQueue, StoringPacketQueue)); 
        executorService.submit(new PacketConsumer(StoringPacketQueue)); 
        executorService.submit(new PacketRetriever(DetectionPacketQueue));
        executorService.submit(new DetectionDispatcher(DetectionPacketQueue));
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
                
                if (parsedPacketData == null || parsedPacketData.isEmpty()) {
                    System.out.println("[PRODUCER] Skipping null or empty parsed packet");
                    continue;
                }
                
                StoringPacketQueue.put(parsedPacketData); // Add parsed data to the storing queue
                System.out.println("[PRODUCER] Packet parsed and added to StoringPacketQueue: " + parsedPacketData);
                //LOGGER.info("[PRODUCER] Packet parsed and added to StoringPacketQueue: " + parsedPacketData);

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
        System.out.println("[RETRIEVER] Thread Started");
        try {
            while (PacketPipelineService.running) {
                //System.out.println("[RETRIEVER]");
                long latestPacketID = PacketRetrieverDao.getLatestPacketID();
                System.out.println("[RETRIEVER] Fetching packet with ID: " + latestPacketID);
                Map<String, Object> packetInfo = PacketRetrieverDao.getPacketData(latestPacketID); 
                System.out.println("[RETRIEVER] Packet Fetched: " + packetInfo);
                detectionQueue.put(packetInfo);
                System.out.println("[RETRIEVER] Packet added to DetectionQueue");
                    
            }
        } catch (InterruptedException e) {
            System.out.println("[ERROR RETRIEVER] ");
            Thread.currentThread().interrupt();
            
        }
    }
}

class DetectionDispatcher implements Runnable {
    private BlockingQueue<Map<String, Object>> detectionQueue;
    private ExecutorService detectionServicePool;
    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(DetectionDispatcher.class);
    

    // Inject your detection services
    private BruteForceService bruteForceService = new BruteForceService();
    private DNSWebFilterService dnsWebFilterService = new DNSWebFilterService();
    private DosService dosService = new DosService();
    private DpiService dpiService = new DpiService();
    private ExtICMPService extICMPService = new ExtICMPService();
    private EvaluatedDao evaluatedDao = new EvaluatedDao();
    //private final MalwareService malwareService = new MalwareService();
    private final SusUserAgentService susUserAgentService = new SusUserAgentService();

    public DetectionDispatcher(BlockingQueue<Map<String, Object>> detectionQueue) {
        this.detectionQueue = detectionQueue;
        this.detectionServicePool = Executors.newFixedThreadPool(6); // 5 detection services in parallel
    }

    @Override
    public void run() {
        System.out.println("[DETECTOR] Thread Started");
        try {
            while (PacketPipelineService.running) {
                //System.out.println("[DETECTOR]");
                Map<String, Object> packetData = detectionQueue.take();
                System.out.println("[DETECTOR] Retrieved packet from queue: " + packetData);
             
                try{
                    System.out.println("[DETECTOR] Packet sent to detection services");
                    detectionServicePool.submit(() -> bruteForceService.loadBruteForce(packetData));
                    detectionServicePool.submit(() -> dnsWebFilterService.loadDnsWebFilterRules(packetData));
                    detectionServicePool.submit(() -> dosService.loadDosService(packetData));
                    detectionServicePool.submit(() -> dpiService.loadDpiDetectorKeywords(packetData));
                    detectionServicePool.submit(() -> extICMPService.loadICMPRules(packetData));
                    //detectionServicePool.submit(() -> malwareService.loadMalwareSig(packetData));
                    detectionServicePool.submit(() -> susUserAgentService.loadSuspiciousUserAgent(packetData));
                    System.out.println("[DETECTOR] Packet Done with detection: " + packetData);
                    EvaluatedDao.evaluated((Long) packetData.get("Packet_ID"));
                    
                    LOGGER.info("[DETECTOR] Packet sent to detection services: " + packetData);
                }catch (Exception e){
                    System.out.println("[ERROR DETECTOR]");
                }
                
            }
        } catch (InterruptedException e) {
            System.out.println("[DONE DETECTOR] ");
            Thread.currentThread().interrupt();
        }
    }
}





 