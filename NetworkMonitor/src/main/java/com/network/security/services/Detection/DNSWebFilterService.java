package com.network.security.services.Detection;

import com.network.security.Dao.Detection.DNSWebFilterDao;
import com.network.security.Intrusion_detection.DNSWebFilterDetector;
import com.network.security.util.DBConnection;
import com.network.security.services.AlertService;

import java.sql.Connection;
//import java.sql.SQLException;
import java.util.Map;

public class DNSWebFilterService {
    private DNSWebFilterDao dnsWebFilterDao = new DNSWebFilterDao();
    private DNSWebFilterDetector dnsWebFilterDetector = new DNSWebFilterDetector();

    private AlertService alertService = new AlertService(); // Assuming you have an AlertService class for alerting
    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(DNSWebFilterService.class);
    Connection conn = DBConnection.getConnection();
 
    // Load DNS Web Filter rules from the database and set them in the detector
    public void loadDnsWebFilterRules(Map<String, Object> packetInfo) {
        try { 
            
            String domain = (String) packetInfo.get("HOST_HEADER");  
            if (domain == null) return;
            String srcIP = (String) packetInfo.get("SRC_IP");
            if (srcIP == null) return;
            String dstIP = (String) packetInfo.get("DST_IP");
            String protocol = (String) packetInfo.get("PROTOCOL");
            if (protocol == null) return;
            
            Integer queryCount = (Integer) packetInfo.getOrDefault("QUERY_COUNT", 1); // Example field for how often it was queried
            Integer secondsElapsed = (Integer) packetInfo.getOrDefault("TIME_ELAPSED", 1); // Example field for time elapsed
            
            System.out.println("[DNS WEB FILTER] Starting DNS Web Filter Function");
            // Load threshold rules based on domain pattern
            if (conn == null) {
                System.out.println("[CONN ERROR] Database connection is null");
                LOGGER.error("[CONN ERROR] Database connection is null");
                return;
            }
            dnsWebFilterDao.loadDnsWebFilterThreshold(conn, domain);
            System.out.println("Thresholds loaded");
            
            
            boolean detected =  dnsWebFilterDetector.detect(domain, queryCount, secondsElapsed);
            // Run detection logic
            if (detected) {
                System.out.println("[ALERT] Potential DNS Web Filtering evasion attempt detected for domain: " + domain);
                LOGGER.info("[ALERT] Potential DNS Web Filtering evasion attempt detected for domain: " + domain);
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
                System.out.println("NO DNS Web Filtering evasion attempt for domain: " + domain);
            }
    
        } catch (Exception e) {
            System.err.println("[ERROR] Failed in DNS Web Filter detection service");
            LOGGER.error("[ERROR] Failed in DNS Web Filter detection service", e);
            e.printStackTrace();
        }
    }
 
}