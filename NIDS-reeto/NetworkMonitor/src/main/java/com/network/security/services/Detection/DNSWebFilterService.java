package com.network.security.services.Detection;

import com.network.security.Dao.Detection.DNSWebFilterDao;
import com.network.security.Intrusion_detection.DNSWebFilterDetector;
import java.sql.Connection;
import java.sql.SQLException;

public class DNSWebFilterService {
    private DNSWebFilterDao dnsWebFilterDao;
    private DNSWebFilterDetector dnsWebFilterDetector;

    public DNSWebFilterService() {
        this.dnsWebFilterDao = new DNSWebFilterDao();
        this.dnsWebFilterDetector = new DNSWebFilterDetector("", 0, 0);
    }

    // Add new DNS Web Filter rule
    public void addDnsWebFilterRule(Connection conn, String pattern, int threshold, int timeWindow) {
        dnsWebFilterDao.insertDnsWebFilterRule(conn, pattern, threshold, timeWindow);
    }

    // Load DNS Web Filter rules from the database and set them in the detector
    public void loadDnsWebFilterRules(Connection conn) {
        dnsWebFilterDao.loadDnsWebFilterRules(conn);
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
