package com.network.security.services.Detection;
 
import com.network.security.Dao.Detection.ExtICMPDao;
import com.network.security.Intrusion_detection.ExtICMPDetection;
import com.network.security.util.DBConnection;
import com.network.security.services.AlertService;

import java.sql.Connection;
import java.util.Map;

public class ExtICMPService {
    private ExtICMPDao extICMPDao;
    private ExtICMPDetection extICMPDetection;
    AlertService alertService = new AlertService(); 
    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(ExtICMPService.class); 
    Connection conn = DBConnection.getConnection();
    // Load from DB
    public void loadICMPRules(Map<String, Object> packetInfo) {
        try { 
            System.out.println("[EXTERNAL ICMP] Starting External ICMP Detection Function");
            String srcIP = (String) packetInfo.get("srcIP");
            String dstIP = (String) packetInfo.get("destIP");
            String protocol = (String) packetInfo.get("PROTOCOL");
            if (srcIP == null || dstIP == null) return;
            
            if (conn == null) {
                System.out.println("[CONN ERROR] Database connection is null");
                LOGGER.error("[CONN ERROR] Database connection is null");
                return;
            }
            extICMPDao.loadICMPip(conn);
            System.out.println("Thresholds loaded");

            if (extICMPDetection == null) {
                extICMPDetection = new ExtICMPDetection();
            }        
            boolean detected = extICMPDetection.detect(srcIP, dstIP);

            if (detected) {
                System.out.println("[ALERT] External ICMP Black attack detected from IP: " + srcIP + " to " + dstIP);
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
            else{
                System.out.println("NO External ICMP Black attack detected from IP: " + srcIP + " to " + dstIP);
            }

        }
        catch (Exception e) {
            System.err.println("[ERROR] Failed to load ICMP detection data");
            LOGGER.error("[ERROR] Failed to load ICMP detection data", e);
            e.printStackTrace();
        }
    }
 
}