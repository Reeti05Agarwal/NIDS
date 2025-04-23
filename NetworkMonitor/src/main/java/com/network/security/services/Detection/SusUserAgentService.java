package com.network.security.services.Detection;

import java.sql.Connection;
import java.util.Map;
import com.network.security.Dao.Detection.SuspiciousUserAgentDao;
import com.network.security.Intrusion_detection.SuspiciousUserAgentDetection;
import com.network.security.util.DBConnection;
import com.network.security.util.PacketUtils;
import com.network.security.services.AlertService;

// System.out.println("[SUS USER AGENT] ");

public class SusUserAgentService {
    SuspiciousUserAgentDetection susUserAgentDetection;
    SuspiciousUserAgentDao susUserAgentDao;
    AlertService alertService = new AlertService(); 
    Connection conn = DBConnection.getConnection();

    public void loadSuspiciousUserAgent(Map<String, Object> packetInfo) {
        try {
            System.out.println("[SUS USER AGENT] Starting Suspicious User Agent Detection Function");
            Integer srcPort = null;
            Integer dstPort = null;
            String srcIP = null;
            String dstIP = null;
            String protocol = null;
            String userAgent = null;

            if (packetInfo.get("srcPort") != null){
            srcPort = (Integer) packetInfo.get("srcPort"); 
            dstPort = (Integer) packetInfo.get("destPort");
            } else {
                System.out.println("[EXTERNAL ICMP] Source and Destination Port is NULL");
                return;
            }
            srcIP = (String) packetInfo.get("srcIP");
            dstIP = (String) packetInfo.get("destIP");
            protocol = (String) packetInfo.getOrDefault("PROTOCOL", "ICMP");
            
         
             
            // Check if the packet is HTTP
            if ("HTTP".equals(PacketUtils.parseGetService(srcPort, dstPort))){
                if (packetInfo.get("user_agent") != null){
                    userAgent = (String) packetInfo.get("user_agent");  
                } else{
                    System.out.println("[EXTERNAL ICMP] User Agent is NULL");
                    return;
                }
                      
                if (conn == null) {
                    System.out.println("[CONN ERROR] Database connection is null");
                    return;
                }

                susUserAgentDao.loadSuspiciousUserAgent(conn); 
                System.out.println("[EXTERNAL ICMP] Thresholds loaded");       
                boolean detected = susUserAgentDetection.detect(userAgent);  

                if (detected) {
                    System.out.println("[ALERT] [HTTP] Suspicious User-Agent detected: " + userAgent);
                    alertService.triggerAlert(
                        conn,
                        srcIP != null ? srcIP : "UNKNOWN",
                        dstIP != null ? dstIP : "UNKNOWN",
                        protocol,
                        4, // Assume rule_id = 4 for External ICMP detection
                        susUserAgentDetection.getSeverity(),
                        "[External ICMP] Blacklisted IP triggered alert"
                    );
                }
                else{
                    System.out.println("[EXTERNAL ICMP] NO Suspicious User-Agent detected: " + userAgent);
                }
            }
        } catch (Exception e) {
            System.err.println("[ERROR] [EXTERNAL ICMP] Failed to load Suspicious User Agent List");
            e.printStackTrace();
        }
        return;
    }
}