package com.network.security.services;

import com.network.security.Dao.AnalyticsDao;
import com.network.security.util.DBConnection;

import java.sql.Connection;
import java.util.Map;

/**
 * Service layer for analytics metrics.
 */
public class AnalyticsService {

    private final AnalyticsDao analyticsDao = new AnalyticsDao();

    public Map<String, Integer> fetchPacketCountsByProtocol() {
        try (Connection conn = DBConnection.getConnection()) {
            return analyticsDao.getPacketCountsByProtocol(conn);
        } catch (Exception e) {
            throw new RuntimeException("Failed to fetch packet counts", e);
        }
    }

    public Map<String, Integer> fetchAlertCountsBySeverity() {
        try (Connection conn = DBConnection.getConnection()) {
            return analyticsDao.getAlertCountsBySeverity(conn);
        } catch (Exception e) {
            throw new RuntimeException("Failed to fetch alert counts", e);
        }
    }

    public Map<String, Integer> fetchTopMaliciousIPs(int limit) {
        try (Connection conn = DBConnection.getConnection()) {
            return analyticsDao.getTopMaliciousIPs(conn, limit);
        } catch (Exception e) {
            throw new RuntimeException("Failed to fetch top malicious IPs", e);
        }
    }

    public Map<String, Integer> fetchAnomalyCounts() {
        try (Connection conn = DBConnection.getConnection()) {
            return analyticsDao.getAnomalyCounts(conn);
        } catch (Exception e) {
            throw new RuntimeException("Failed to fetch anomaly counts", e);
        }
    }
}
