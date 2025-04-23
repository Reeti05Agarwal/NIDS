package com.network.security.services.Detection;
 
import com.network.security.Dao.Detection.ExtICMPDao;
import com.network.security.Intrusion_detection.ExtICMPDetection;
import com.network.security.util.DBConnection;
import com.network.security.services.AlertService;
import java.sql.Connection;
import java.util.Map;

// System.out.println("[EXTERNAL ICMP] ");

public class ExtICMPService {
    private ExtICMPDao extICMPDao;
    private ExtICMPDetection extICMPDetection;
    AlertService alertService = new AlertService(); 
    Connection conn = DBConnection.getConnection();
    
    public void loadICMPRules(Map<String, Object> packetInfo) {
        try { 
            System.out.println("[EXTERNAL ICMP] Starting External ICMP Detection Function");
            String srcIP = null;
            String dstIP = null;
            String protocol = null;
            
            if (packetInfo.get("srcIP") != null){
                srcIP = (String) packetInfo.get("srcIP");
                dstIP = (String) packetInfo.get("destIP");
            } else {
                System.out.println("[EXTERNAL ICMP] Source and Destination IP is NULL");
                return;
            }
            protocol = (String) packetInfo.get("PROTOCOL");
             
            if (conn == null) {
                System.out.println("[CONN ERROR] Database connection is null");
                return;
            }
            extICMPDao.loadICMPip(conn);
            System.out.println("[EXTERNAL ICMP] Thresholds loaded"); 
            boolean detected = extICMPDetection.detect(srcIP, dstIP);

            if (detected) {
                System.out.println("[ALERT] External ICMP Black attack detected from IP: " + srcIP + " to " + dstIP);
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
                System.out.println("[EXTERNAL ICMP] NO External ICMP Black attack detected from IP: " + srcIP + " to " + dstIP);
            }

        }
        catch (Exception e) {
            System.err.println("[ERROR] [EXTERNAL ICMP] Failed to load ICMP detection data");
            e.printStackTrace();
        }
    }
 
}