package com.network.security.services.Detection;

import com.network.security.Dao.Detection.DNSWebFilterDao;
import com.network.security.Intrusion_detection.DNSWebFilterDetector;
import com.network.security.util.DBConnection;
import com.network.security.services.AlertService;
import java.sql.Connection;
import java.util.Map;

// System.out.println("[DNS WEB FILTER] ");

public class DNSWebFilterService {
    private DNSWebFilterDao dnsWebFilterDao = new DNSWebFilterDao();
    private DNSWebFilterDetector dnsWebFilterDetector = new DNSWebFilterDetector();
    private AlertService alertService = new AlertService();  
    Connection conn = DBConnection.getConnection();
 
    // Load DNS Web Filter rules from the database and set them in the detector
    public void loadDnsWebFilterRules(Map<String, Object> packetInfo) {
        try { 
            System.out.println("[DNS WEB FILTER] Starting DNS Web Filter Function");
            String domain = null;
            String srcIP = null;
            String dstIP = null;
            String protocol = null;
            
            if (packetInfo.get("HOST") != null){
                domain = (String) packetInfo.get("HOST");  
            }
            else{
                System.out.println("[DNS WEB FILTER] Host/Domain is NULL");
                return;
            } 
            if (packetInfo.get("PROTOCOL") != null){
                protocol = (String) packetInfo.get("PROTOCOL");
            }else{
                System.out.println("[DNS WEB FILTER] Protocol is NULL");
                return;
            }
            
            Integer queryCount = (Integer) packetInfo.getOrDefault("QUERY_COUNT", 1); // Example field for how often it was queried
            Integer secondsElapsed = (Integer) packetInfo.getOrDefault("TIME_ELAPSED", 1); // Example field for time elapsed
            System.out.println("[DNS WEB FILTER] Query Count: " + queryCount);
            System.out.println("[DNS WEB FILTER] Seconds Elapsed: " + secondsElapsed);

            if (conn == null) {
                System.out.println("[CONN ERROR] Database connection is null");
                return;
            }
            dnsWebFilterDao.loadDnsWebFilterThreshold(conn, domain);
            System.out.println("[DNS WEB FILTER] Thresholds loaded");
            boolean detected =  dnsWebFilterDetector.detect(domain, queryCount, secondsElapsed);
            
            if (detected) {
                System.out.println("[ALERT] Potential DNS Web Filtering evasion attempt detected for domain: " + domain);
                alertService.triggerAlert(
                    conn,
                    srcIP != null ? srcIP : "UNKNOWN",
                    dstIP != null ? dstIP : "UNKNOWN",
                    protocol != null ? protocol : "UNKNOWN",
                    4, // Assume rule_id = 4 for DNS filtering (adjust accordingly)
                    dnsWebFilterDetector.getSeverity(),
                    "[DNS Web Filter] Suspicious domain query detected: " + domain
                );
            }
            else{
                System.out.println("[DNS WEB FILTER] NO DNS Web Filtering evasion attempt for domain: " + domain);
            }
    
        } catch (Exception e) {
            System.err.println("[ERROR DNS WEB FILTER] Failed in DNS Web Filter detection service");
            e.printStackTrace();
        }
    }
 
}