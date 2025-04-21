package com.network.security.services.Detection;

import com.network.security.Dao.Detection.DpiDetectorDao;
import com.network.security.Intrusion_detection.DpiDetector;
import com.network.security.util.MYSQLconnection;
import com.network.security.services.AlertService; 

import java.sql.Connection;
import java.util.Map;

public class DpiService {
    private DpiDetectorDao dpiDetectorDao;
    private DpiDetector dpiDetector;
    AlertService alertService = new AlertService(); 
    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(BruteForceService.class);  
    Connection conn = MYSQLconnection.getConnection();

    // Add a new DPI detection keyword
    public void loadDpiDetectorKeywords(Map<String, Object> packetInfo) {
         try {
            String payload = (String) packetInfo.get("TCP_PAYLOAD");
            String srcIP = (String) packetInfo.get("SRC_IP");
            String destIP = (String) packetInfo.get("DST_IP");
            String protocol = (String) packetInfo.get("PROTOCOL");
            
            if (payload == null) return;

            dpiDetectorDao.loadDpiDetector(conn);
            boolean detected = dpiDetector.detect(payload);  

            if (detected) {
                System.out.println("Deep Packet Inspection detected malicious Strings: " + payload);
                LOGGER.info("Deep Packet Inspection detected malicious Strings: " + payload);
                alertService.triggerAlert(
                    conn,
                    srcIP != null ? srcIP : "UNKNOWN",
                    destIP != null ? destIP : "UNKNOWN",
                    protocol != null ? protocol : "UNKNOWN",
                    3, // Assume rule_id = 3 for DPI detection
                    dpiDetector.getSeverity(),
                    "[DPI Detection] Malicious payload string matched: " + payload
                );
            }


        } catch (Exception e) {
            System.err.println("[ERROR] Failed to add DPI detection keyword");
            LOGGER.error("[ERROR] Failed to add DPI detection keyword", e);
            e.printStackTrace();
        }
    }
}