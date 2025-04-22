package com.network.security.services;

import java.util.Map;
import java.util.concurrent.BlockingQueue;
//import java.util.concurrent.CountDownLatch;
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

import com.network.security.services.Detection.BruteForceService;
import com.network.security.services.Detection.DNSWebFilterService;
import com.network.security.services.Detection.DosService;
import com.network.security.services.Detection.DpiService;
import com.network.security.services.Detection.ExtICMPService;
import com.network.security.services.Detection.SusUserAgentService;
 
/*
 * Anonymous Thread 
 * PacketProducer
 * PacketConsumer
 * PacketRetriever
 * DetectionDispatcher
 * 
 * CountDownLatch to sequence thread startup
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

        // CountDownLatch latch1 = new CountDownLatch(1);
        // CountDownLatch latch2 = new CountDownLatch(1);
        // CountDownLatch latch3 = new CountDownLatch(1);
        // CountDownLatch latch4 = new CountDownLatch(1);

        // PacketProducer packetproducer = new PacketProducer(RawPacketQueue, StoringPacketQueue);
        // PacketConsumer packetconsumer = new PacketConsumer(StoringPacketQueue);
        // PacketRetriever retriever = new PacketRetriever(DetectionPacketQueue);
        // DetectionDispatcher detector = new DetectionDispatcher(DetectionPacketQueue);

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

        /*
        executorService.submit(() -> {
            try (PcapHandle handle = device.openLive(snapshotLength, PromiscuousMode.PROMISCUOUS, readTimeout)) {
                handle.loop(-1, listener); // Capture packets infinitely
            } catch (Exception e) {
                LOGGER.error("Error during packet capture", e);
            } finally {
                latch1.countDown(); // Signal producer to start
            }
        });
        
        // 2. PacketProducer
        executorService.submit(() -> {
            try {
                latch1.await(); // Wait for capture
            } catch (InterruptedException ignored) {}
            
            executorService.submit(() -> {
                new PacketProducer(RawPacketQueue, StoringPacketQueue).run(); // This runs forever
            });
            latch2.countDown(); // Signal consumer to start
        });
        
        // 3. PacketConsumer
        executorService.submit(() -> {
            try {
                latch2.await(); // Wait for producer
            } catch (InterruptedException ignored) {}
            
            executorService.submit(() -> {
                new PacketConsumer(StoringPacketQueue).run(); // Also runs forever
            });
            latch3.countDown(); // Signal retriever
        });
        
        // 4. PacketRetriever
        executorService.submit(() -> {
            try {
                latch3.await(); // Wait for consumer
            } catch (InterruptedException ignored) {}
            
            executorService.submit(() -> {
                new PacketRetriever(DetectionPacketQueue).run();
            });
            latch4.countDown(); // Signal detector
        });
        
        // 5. DetectionDispatcher
        executorService.submit(() -> {
            try {
                latch4.await(); // Wait for retriever
            } catch (InterruptedException ignored) {}
        
            executorService.submit(() -> {
                new DetectionDispatcher(DetectionPacketQueue).run();
            });
        });
         */
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

                //PacketDao.processPacket(PacketData); // Process the packet data
                //System.out.println("[CONSUMER] Packet processed and stored: " + PacketData);
                //LOGGER.info("[CONSUMER] Packet processed and stored: " + PacketData);
                
                try{
                    PacketDao.processPacket(PacketData); // Process the packet data
                    System.out.println("[CONSUMER] Packet processed and stored: " + PacketData);
                    LOGGER.info("[CONSUMER] Packet processed and stored: " + PacketData);
                }catch (Exception e){
                    System.out.println("[ERROR] problem with packet dao");
                } 
                
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
                System.out.println("[RETRIEVER]");
                // simulate polling every 5 seconds, or poll only unprocessed packets
             
                long latestPacketID = PacketRetrieverDao.getLatestPacketID(); // Loading latest packet ID
                System.out.println("[RETRIEVER] Fetching packet with ID: " + latestPacketID);
                LOGGER.info("[RETRIEVER] Fetching packet with ID: " + latestPacketID);
                Map<String, Object> packetInfo = PacketRetrieverDao.getPacketData(latestPacketID); // Loading packet data
                System.out.println("[RETRIEVER] Packet Fetched: " + packetInfo);


                for (Map.Entry<String, Object> packet : packetInfo.entrySet()) {
                    Map<String, Object> singlePacketMap = Map.of(packet.getKey(), packet.getValue());
                    detectionQueue.put(singlePacketMap);
                    System.out.println("[RETRIEVER] Packet fetched from DB and added to DetectionQueue");
                    LOGGER.info("[RETRIEVER] Packet fetched from DB and added to DetectionQueue: " + singlePacketMap);
                }

                sleepWithInterruptCheck(5000);
            }
        } catch (InterruptedException e) {
            System.out.println("[ERROR RETRIEVER] ");
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
                System.out.println("[DETECTOR]");
                Map<String, Object> packetData = detectionQueue.take();
                System.out.println("[DETECTOR] Retrieved packet from queue: " + packetData);
                LOGGER.info("[DETECTOR] Retrieved packet from queue: " + packetData);

                
                detectionServicePool.submit(() -> bruteForceService.loadBruteForce(packetData));
                detectionServicePool.submit(() -> dnsWebFilterService.loadDnsWebFilterRules(packetData));
                detectionServicePool.submit(() -> dosService.loadDosService(packetData));
                detectionServicePool.submit(() -> dpiService.loadDpiDetectorKeywords(packetData));
                detectionServicePool.submit(() -> extICMPService.loadICMPRules(packetData));
                //detectionServicePool.submit(() -> malwareService.loadMalwareSig(packetData));
                detectionServicePool.submit(() -> susUserAgentService.loadSuspiciousUserAgent(packetData));
                
                System.out.println("[DETECTOR] Packet sent to detection services: " + packetData);
                LOGGER.info("[DETECTOR] Packet sent to detection services: " + packetData);
            }
        } catch (InterruptedException e) {
            System.out.println("[ERROR DETECTOR] ");
            Thread.currentThread().interrupt();
        }
    }
}





 