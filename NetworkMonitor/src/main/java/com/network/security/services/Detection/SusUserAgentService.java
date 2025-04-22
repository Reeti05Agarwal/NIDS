package com.network.security.services.Detection;

import java.sql.Connection;
import java.util.Map;
import com.network.security.Dao.Detection.SuspiciousUserAgentDao;
import com.network.security.Intrusion_detection.SuspiciousUserAgentDetection;
import com.network.security.util.DBConnection;
import com.network.security.util.PacketUtils;
import com.network.security.services.AlertService;

public class SusUserAgentService {
    SuspiciousUserAgentDetection susUserAgentDetection;
    SuspiciousUserAgentDao susUserAgentDao;
    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(SusUserAgentService.class);
    AlertService alertService = new AlertService(); 
    Connection conn = DBConnection.getConnection();

    public void loadSuspiciousUserAgent(Map<String, Object> packetInfo) {
        try {
            System.out.println("[SUS USER AGENT] Starting Suspicious User Agent Detection Function");
            Integer srcPort = (Integer) packetInfo.get("srcPort"); 
            if (srcPort == null) return;
            Integer dstPort = (Integer) packetInfo.get("destPort");
            String srcIP = (String) packetInfo.get("srcIP");
            if (srcIP == null) return;
            String dstIP = (String) packetInfo.get("destIP");
            String protocol = (String) packetInfo.getOrDefault("PROTOCOL", "ICMP");
            
            if (srcPort == -1) {
                LOGGER.warn("SRC_PORT is null or invalid in the packet: " + packetInfo);
                return; // Exit from the method or continue with the next iteration
            }
            
            if (dstPort == -1) {
                LOGGER.warn("DST_PORT is null or invalid in the packet: " + packetInfo);
                return; // Exit from the method or continue with the next iteration
            }
             
            // Check if the packet is HTTP
            if ("HTTP".equals(PacketUtils.parseGetService(srcPort, dstPort))){
                String userAgent = (String) packetInfo.get("user_agent");  
                if (userAgent == null) return; 

                if (conn == null) {
                    System.out.println("[CONN ERROR] Database connection is null");
                    LOGGER.error("[CONN ERROR] Database connection is null");
                    return;
                }
                susUserAgentDao.loadSuspiciousUserAgent(conn); 
                System.out.println("Thresholds loaded"); 

                if (susUserAgentDetection == null) {
                    susUserAgentDetection = new SuspiciousUserAgentDetection();
                }        
                boolean detected = susUserAgentDetection.detect(userAgent);  

                if (detected) {
                    System.out.println("[ALERT] [HTTP] Suspicious User-Agent detected: " + userAgent);
                    LOGGER.info("[HTTP] Suspicious User-Agent detected: " + userAgent);
                    alertService.triggerAlert(
                        conn,
                        srcIP != null ? srcIP : "UNKNOWN",
                        dstIP != null ? dstIP : "UNKNOWN",
                        protocol,
                        4, // Assume rule_id = 4 for External ICMP detection
                        susUserAgentDetection.getSeverity(),
                        "[External ICMP Detection] Blacklisted IP triggered alert"
                    );
                }
                else{
                    System.out.println("NO Suspicious User-Agent detected: " + userAgent);
                }
            }
        } catch (Exception e) {
            System.err.println("[ERROR] Failed to load Suspicious User Agent List");
            LOGGER.error("[ERROR] Failed to load Suspicious User Agent List", e);
            e.printStackTrace();
        }
        return;
    }
}