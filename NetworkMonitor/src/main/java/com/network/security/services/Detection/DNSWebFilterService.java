package com.network.security.services.Detection;

import com.network.security.Dao.Detection.DNSWebFilterDao;
import com.network.security.Intrusion_detection.DNSWebFilterDetector;
import com.network.security.util.MYSQLconnection;
import com.network.security.Dao.PacketRetrieverDao;

import java.sql.Connection;
//import java.sql.SQLException;
import java.util.Map;

public class DNSWebFilterService {
    private DNSWebFilterDao dnsWebFilterDao;
    private DNSWebFilterDetector dnsWebFilterDetector;
    PacketRetrieverDao packetRetrieverDao;

    MYSQLconnection mysqlConnection;
    Connection conn = MYSQLconnection.getConnection();
 
    // Load DNS Web Filter rules from the database and set them in the detector
    public void loadDnsWebFilterRules(Connection conn) {
        try {
            long latestPacketID = PacketRetrieverDao.getLatestPacketID(); // Loading latest packet ID
            Map<String, Object> packetInfo = PacketRetrieverDao.getPacketData(latestPacketID); // Loading packet data
    
            String domain = (String) packetInfo.get("HOST_HEADER"); // Could also be under PAYLOAD in some cases
            int queryCount = (int) packetInfo.getOrDefault("QUERY_COUNT", 1); // Example field for how often it was queried
            int secondsElapsed = (int) packetInfo.getOrDefault("TIME_ELAPSED", 1); // Example field for time elapsed
    
            // Load threshold rules based on domain pattern
            dnsWebFilterDao.loadDnsWebFilterThreshold(conn, domain);
    
            // Run detection logic
            if (dnsWebFilterDetector.detect(domain, queryCount, secondsElapsed)) {
                System.out.println("[ALERT] Potential DNS Web Filtering evasion attempt detected for domain: " + domain);
            }
    
        } catch (Exception e) {
            System.err.println("[ERROR] Failed in DNS Web Filter detection service");
            e.printStackTrace();
        }
    }

    // Add new DNS Web Filter rule
    public void addDnsWebFilterRule(Connection conn, String pattern, int threshold, int timeWindow) {
        dnsWebFilterDao.insertDnsWebFilterRule(conn, pattern, threshold, timeWindow);
    }

    

    // Update the threshold for a DNS Web Filter rule
    public void updateDnsWebFilterThreshold(Connection conn, int newThreshold, int id) {
        dnsWebFilterDao.updateDnsWebFilterThreshold(conn, newThreshold, id);
    }

    // Update the time window for a DNS Web Filter rule
    public void updateDnsWebFilterTimeWindow(Connection conn, int newTimeWindow, int id) {
        dnsWebFilterDao.updateDnsWebFilterTimeWindow(conn, newTimeWindow, id);
    }

    // Delete a DNS Web Filter rule from the database
    public void deleteDnsWebFilterRule(Connection conn, int id) {
        dnsWebFilterDao.deleteDnsWebFilterRule(conn, id);
    }

    // Detect DNS Web Filter attack based on the query, count, and time elapsed
    public boolean detectDnsWebFilterAttack(String dnsQuery, int queryCount, int secondsElapsed) {
        // Load current rules into the detector before detection
        loadDnsWebFilterRules(null);  // You can pass an actual connection here
        return dnsWebFilterDetector.detect(dnsQuery, queryCount, secondsElapsed);
    }
}