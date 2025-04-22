package com.network.security.services.Detection;

import com.network.security.Dao.Detection.DpiDetectorDao;
import com.network.security.Intrusion_detection.DpiDetector;
import com.network.security.util.DBConnection;
import com.network.security.services.AlertService; 

import java.sql.Connection;
import java.util.Map;

public class DpiService {
    private DpiDetectorDao dpiDetectorDao;
    private DpiDetector dpiDetector;
    AlertService alertService = new AlertService(); 
    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(BruteForceService.class);  
    Connection conn = DBConnection.getConnection();

    // Add a new DPI detection keyword
    public void loadDpiDetectorKeywords(Map<String, Object> packetInfo) {
         try {
            System.out.println("[DPI KEYWORDS] Starting DPI Keywords Detection Function");
            String payload = (String) packetInfo.get("PAYLOAD");
            // Removed redundant payload null check
            String srcIP = (String) packetInfo.get("srcIP");
            if (srcIP == null) return;
            String destIP = (String) packetInfo.get("destIP");
            String protocol = (String) packetInfo.get("PROTOCOL");
            if (payload == null) return;

            if (conn == null) {
                System.out.println("[CONN ERROR] Database connection is null");
                LOGGER.error("[CONN ERROR] Database connection is null");
                return;
            }
            dpiDetectorDao.loadDpiDetector(conn);
            System.out.println("Thresholds loaded");
            boolean detected = dpiDetector.detect(payload);  

            if (detected) {
                System.out.println("[ALERT] Deep Packet Inspection detected malicious Strings: " + payload);
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
            else{
                System.out.println("NO Deep Packet Inspection malicious Strings: " + payload);
            }


        } catch (Exception e) {
            System.err.println("[ERROR] Failed to add DPI detection keyword");
            LOGGER.error("[ERROR] Failed to add DPI detection keyword", e);
            e.printStackTrace();
        }
    }
}