package com.network.security.services.Detection;

import java.util.ArrayList;
import java.util.List;
import java.util.Map; 
import java.util.HashMap;
import java.sql.Connection;

import com.network.security.Dao.PacketRetrieverDao;
import com.network.security.Dao.Detection.BruteForceDao;
import com.network.security.Intrusion_detection.BruteForceDetector; 
import com.network.security.util.MYSQLconnection;
import com.network.security.util.PacketUtils;
import com.network.security.services.AlertService; // Assuming you have an AlertService class for alerting

public class BruteForceService {
    BruteForceDetector bruteForceDetector;
    PacketRetrieverDao packetRetrieverDao; 
    AlertService alertService = new AlertService(); // Assuming you have an AlertService class for alerting
    BruteForceDao bruteForceDao = new BruteForceDao();
    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(BruteForceService.class);


    private Map<String, List<Long>> packetTimestamps = new HashMap<>();
    Connection conn = MYSQLconnection.getConnection();

    public void loadBruteForce(Map<String, Object> packetInfo) {
        try { 
            Object srcPort = packetInfo.get("SRC_PORT"); 
            Object dstPort = packetInfo.get("DST_PORT");
            String srcIP = (String) packetInfo.get("SRC_IP");
            String dstIP = (String) packetInfo.get("DST_IP");

            int srcPortInt = Integer.parseInt(srcPort.toString()); 
            int dstPortInt = Integer.parseInt(dstPort.toString());
            String service = PacketUtils.parseGetService(srcPortInt, dstPortInt); 
            if (service == null) return;

            bruteForceDao.loadBruteForceThresholds(conn, service); 
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
                System.out.println("[" + service + "] Brute Force attack detected from IP: " + srcIP);
                LOGGER.info("[" + service + "] Brute Force attack detected from IP: " + srcIP);
                alertService.triggerAlert(
                    conn,
                    srcIP,
                    dstIP != null ? dstIP : "UNKNOWN", // default fallback if dstIP not found
                    service.toUpperCase(), // protocol
                    1, // assuming rule_id 1 for now, should ideally be passed or mapped
                    "Critical",
                    "Brute Force attack detected on " + service + " from IP: " + srcIP
                );
            
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
        packetTimestamps.putIfAbsent(key, new ArrayList<>());
        packetTimestamps.get(key).add(timestamp);
    }

    private void cleanOldTimestamps(List<Long> timestamps, long now) {
        // Calling Time window from bruteForceDetector
        int timeWindow = bruteForceDetector.getBruteTimeWindow();
        timestamps.removeIf(ts -> now - ts > timeWindow);
    }

}
