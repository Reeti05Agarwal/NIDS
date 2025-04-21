package com.network.security.services.Detection;

import com.network.security.Dao.Detection.DNSWebFilterDao;
import com.network.security.Intrusion_detection.DNSWebFilterDetector;
import com.network.security.util.MYSQLconnection;
import com.network.security.services.AlertService;

import java.sql.Connection;
//import java.sql.SQLException;
import java.util.Map;

public class DNSWebFilterService {
    private DNSWebFilterDao dnsWebFilterDao;
    private DNSWebFilterDetector dnsWebFilterDetector;
    private AlertService alertService = new AlertService(); // Assuming you have an AlertService class for alerting
    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(DNSWebFilterService.class);
    Connection conn = MYSQLconnection.getConnection();
 
    // Load DNS Web Filter rules from the database and set them in the detector
    public void loadDnsWebFilterRules(Map<String, Object> packetInfo) {
        try { 
            String domain = (String) packetInfo.get("HOST_HEADER"); // Could also be under PAYLOAD in some cases
            String srcIP = (String) packetInfo.get("SRC_IP");
            String dstIP = (String) packetInfo.get("DST_IP");
            String protocol = (String) packetInfo.get("PROTOCOL");
            
            int queryCount = (int) packetInfo.getOrDefault("QUERY_COUNT", 1); // Example field for how often it was queried
            int secondsElapsed = (int) packetInfo.getOrDefault("TIME_ELAPSED", 1); // Example field for time elapsed
    
            // Load threshold rules based on domain pattern
            dnsWebFilterDao.loadDnsWebFilterThreshold(conn, domain);
    
            // Run detection logic
            if (dnsWebFilterDetector.detect(domain, queryCount, secondsElapsed)) {
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
    
        } catch (Exception e) {
            System.err.println("[ERROR] Failed in DNS Web Filter detection service");
            LOGGER.error("[ERROR] Failed in DNS Web Filter detection service", e);
            e.printStackTrace();
        }
    }
 
}