package com.network.security.services.Detection;

import java.sql.Connection;
import java.util.Map;

import com.network.security.Dao.Detection.DNSWebFilterDao;
import com.network.security.Dao.PacketRetrieverDao;
import com.network.security.Intrusion_detection.DNSWebFilterDetector;
import com.network.security.util.DBConnection;

public class DNSWebFilterService {

    private DNSWebFilterDao dnsWebFilterDao;
    private DNSWebFilterDetector dnsWebFilterDetector;
    PacketRetrieverDao packetRetrieverDao;

    DBConnection mysqlConnection;
    Connection conn = DBConnection.getConnection();

    // Load DNS Web Filter rules from the database and set them in the detector
    public void loadDnsWebFilterRules(Map<String, Object> packetInfo) {
        try {
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

}
