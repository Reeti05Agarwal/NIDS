package com.network.security.services.Detection;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap; // Importing ConcurrentHashMap
import java.sql.Connection; 
import com.network.security.Dao.Detection.BruteForceDao;
import com.network.security.Intrusion_detection.BruteForceDetector; 
import com.network.security.util.DBConnection;
import com.network.security.util.PacketUtils;
import com.network.security.services.AlertService; // Assuming you have an AlertService class for alerting

public class BruteForceService {
    BruteForceDetector bruteForceDetector = new BruteForceDetector();
    AlertService alertService = new AlertService(); // Assuming you have an AlertService class for alerting
    BruteForceDao bruteForceDao = new BruteForceDao();
    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(BruteForceService.class);

    private Map<String, List<Long>> packetTimestamps = new ConcurrentHashMap<>();
    Connection conn = DBConnection.getConnection();

    public void loadBruteForce(Map<String, Object> packetInfo) {
        try { 
            System.out.println("[BRUTE FORCE] Starting Brute Force Detection Function");
            Integer srcPort = (Integer) packetInfo.get("srcPort"); 
            
            Integer dstPort = (Integer) packetInfo.get("destPort");
            String srcIP = (String) packetInfo.get("srcIP");
            String dstIP = (String) packetInfo.get("destIP");

            System.out.println("[BRUTE FORCE] " + srcIP);
            //if (srcIP == null) return;
            System.out.println("[BRUTE FORCE] " + srcPort);
            System.out.println("[BRUTE FORCE] " + dstPort);
            //if (srcPort == null && dstPort == null) return;

            String service = PacketUtils.parseGetService(srcPort, dstPort); // SERVICE
            System.out.println(service);
            if (service == null) return;

            
            if (conn == null) {
                System.out.println("[CONN ERROR] Database connection is null");
                LOGGER.error("[CONN ERROR] Database connection is null");
                return;
            }
            bruteForceDao.loadBruteForceThresholds(conn, service); 
            System.out.println("Thresholds loaded for SSH brute force detection.");
            LOGGER.info("Thresholds loaded for SSH brute force detection.");

            long timestamp = System.currentTimeMillis() / 1000; 
            addPacketTimestamp(service, srcIP, timestamp);  

            List<Long> timestamps = packetTimestamps.get(getKey(service, srcIP));
            cleanOldTimestamps(timestamps, timestamp);  

            int packetCount = timestamps.size();
            int elapsedTime = (int) (timestamp - timestamps.get(0)); 

            if (bruteForceDetector == null) {
                bruteForceDetector = new BruteForceDetector();
            }        
            boolean detected = bruteForceDetector.detect(packetCount, elapsedTime);

            if (detected) {
                System.out.println("[ALERT] [" + service + "] Brute Force attack detected from IP: " + srcIP);
                LOGGER.info("[" + service + "] Brute Force attack detected from IP: " + srcIP);
                alertService.triggerAlert(
                    conn,
                    srcIP != null ? srcIP : "UNKNOWN",
                    dstIP != null ? dstIP : "UNKNOWN", // default fallback if dstIP not found
                    service.toUpperCase(), // protocol
                    1, // assuming rule_id 1 for now, should ideally be passed or mapped
                    bruteForceDetector.getSeverity(),
                    "Brute Force attack detected on " + service + " from IP: " + srcIP
                );
            }
            else {
                System.out.println("Brute Force attack NOT detected from IP: " + srcIP);
            }
        } catch (Exception e) {
            System.err.println("[ERROR] Failed to load brute force detection data");
            LOGGER.error("[ERROR] Failed to load brute force detection data", e);
            e.printStackTrace();
        }
    }

    private String getKey(String service, String srcIP) {
        return service + "_" + srcIP;
    }

    private void addPacketTimestamp(String service, String srcIP, long timestamp) {
        String key = getKey(service, srcIP);
        // Thread-safe operation for adding a timestamp
        packetTimestamps.putIfAbsent(key, new ArrayList<>());
        packetTimestamps.get(key).add(timestamp);
    }

    private void cleanOldTimestamps(List<Long> timestamps, long now) {
        // Calling Time window from bruteForceDetector
        int timeWindow = bruteForceDetector.getBruteTimeWindow();
        if (timestamps != null) {
            timestamps.removeIf(ts -> now - ts > timeWindow);
        }
    }
}
