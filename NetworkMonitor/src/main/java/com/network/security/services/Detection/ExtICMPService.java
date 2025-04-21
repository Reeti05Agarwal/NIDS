package com.network.security.services.Detection;
 
import com.network.security.Dao.Detection.ExtICMPDao;
import com.network.security.Intrusion_detection.ExtICMPDetection;
import com.network.security.util.MYSQLconnection;
import com.network.security.services.AlertService;

import java.sql.Connection;
import java.util.Map;

public class ExtICMPService {
    private ExtICMPDao extICMPDao;
    private ExtICMPDetection extICMPDetection;
    AlertService alertService = new AlertService(); 
    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(ExtICMPService.class); 
    Connection conn = MYSQLconnection.getConnection();
    // Load from DB
    public void loadICMPRules(Map<String, Object> packetInfo) {
        try { 
            String srcIP = (String) packetInfo.get("SRC_IP");
            String dstIP = (String) packetInfo.get("DST_IP");
            String protocol = (String) packetInfo.getOrDefault("PROTOCOL", "ICMP");

            extICMPDao.loadICMPip(conn);

            if (extICMPDetection == null) {
                extICMPDetection = new ExtICMPDetection();
            }        
            boolean detected = extICMPDetection.detect(srcIP, dstIP);

            if (detected) {
                System.out.println("External ICMP Black attack detected from IP: " + srcIP + " to " + dstIP);
                LOGGER.info("External ICMP Black attack detected from IP: " + srcIP + " to " + dstIP);
                alertService.triggerAlert(
                    conn,
                    srcIP != null ? srcIP : "UNKNOWN",
                    dstIP != null ? dstIP : "UNKNOWN",
                    protocol,
                    4, // Assume rule_id = 4 for External ICMP detection
                    extICMPDetection.getSeverity(),
                    "[External ICMP Detection] Blacklisted IP triggered alert"
                );
            }

        }
        catch (Exception e) {
            System.err.println("[ERROR] Failed to load ICMP detection data");
            LOGGER.error("[ERROR] Failed to load ICMP detection data", e);
            e.printStackTrace();
        }
    }
 
}