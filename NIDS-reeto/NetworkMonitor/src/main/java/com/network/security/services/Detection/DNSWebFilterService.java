package com.network.security.services.Detection;

import com.network.security.Dao.Detection.DNSWebFilterDao;
import com.network.security.Intrusion_detection.DNSWebFilterDetector;
import com.network.security.util.MYSQLconnection;
import com.network.security.Dao.PacketRetrieverDao;
import com.network.security.Service.AlertService;

import java.sql.Connection;
import java.util.Map;

public class DNSWebFilterService {
    private DNSWebFilterDao dnsWebFilterDao = new DNSWebFilterDao();
    private DNSWebFilterDetector dnsWebFilterDetector = new DNSWebFilterDetector();
    private PacketRetrieverDao packetRetrieverDao;
    private AlertService alertService = new AlertService();

    MYSQLconnection mysqlConnection;
    Connection conn = MYSQLconnection.getConnection();
 
    // Load DNS Web Filter rules from the database and set them in the detector
    public void loadDnsWebFilterRules(Map<String, Object> packetInfo) {
        try { 
            String domain = (String) packetInfo.get("HOST_HEADER"); // Could also be under PAYLOAD
            String srcIP = (String) packetInfo.get("SRC_IP");
            String dstIP = (String) packetInfo.get("DST_IP");
            String protocol = (String) packetInfo.get("PROTOCOL");

            int queryCount = (int) packetInfo.getOrDefault("QUERY_COUNT", 1); 
            int secondsElapsed = (int) packetInfo.getOrDefault("TIME_ELAPSED", 1); 
    
            dnsWebFilterDao.loadDnsWebFilterThreshold(conn, domain);
    
            if (dnsWebFilterDetector.detect(domain, queryCount, secondsElapsed)) {
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
    
        } catch (Exception e) {
            System.err.println("[ERROR] Failed in DNS Web Filter detection service");
            e.printStackTrace();
        }
    }
}
