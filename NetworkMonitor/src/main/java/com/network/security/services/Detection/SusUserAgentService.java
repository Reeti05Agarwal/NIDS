package com.network.security.services.Detection;

import java.sql.Connection;
import java.util.Map;
import com.network.security.Dao.Detection.SuspiciousUserAgentDao;
import com.network.security.Intrusion_detection.SuspiciousUserAgentDetection;
import com.network.security.util.MYSQLconnection;
import com.network.security.util.PacketUtils;
import com.network.security.services.AlertService;

public class SusUserAgentService {
    SuspiciousUserAgentDetection susUserAgentDetection;
    SuspiciousUserAgentDao susUserAgentDao;
    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(SusUserAgentService.class);
    AlertService alertService = new AlertService(); 
    Connection conn = MYSQLconnection.getConnection();

    public void loadSuspiciousUserAgent(Map<String, Object> packetInfo) {
        try {
            Object srcPort = packetInfo.get("SRC_PORT"); 
            Object dstPort = packetInfo.get("DST_PORT");
            String srcIP = (String) packetInfo.get("SRC_IP");
            String dstIP = (String) packetInfo.get("DST_IP");
            String protocol = (String) packetInfo.getOrDefault("PROTOCOL", "ICMP");


            // Check if the packet is HTTP
            if (PacketUtils.parseGetService((int) srcPort, (int) dstPort) == "HTTP"){
                String userAgent = (String) packetInfo.get("USER_AGENT");  
                if (userAgent == null) return;  

                susUserAgentDao.loadSuspiciousUserAgent(conn);  

                if (susUserAgentDetection == null) {
                    susUserAgentDetection = new SuspiciousUserAgentDetection();
                }        
                boolean detected = susUserAgentDetection.detect(userAgent);  

                if (detected) {
                    System.out.println("[HTTP] Suspicious User-Agent detected: " + userAgent);
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
            }
        } catch (Exception e) {
            System.err.println("[ERROR] Failed to load Suspicious User Agent List");
            LOGGER.error("[ERROR] Failed to load Suspicious User Agent List", e);
            e.printStackTrace();
        }
        return;
    }
}
