package com.network.security.Dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * DAO for querying analytics metrics.
 */
public class AnalyticsDao {

    /**
     * Real‑time traffic: number of packets seen per protocol.
     */
    public Map<String, Integer> getPacketCountsByProtocol(Connection conn) throws Exception {
        String sql = "SELECT protocol, COUNT(*) AS cnt FROM packets GROUP BY protocol";
        try (PreparedStatement ps = conn.prepareStatement(sql); ResultSet rs = ps.executeQuery()) {
            Map<String, Integer> m = new LinkedHashMap<>();
            while (rs.next()) {
                m.put(rs.getString("protocol"), rs.getInt("cnt"));
            }
            return m;
        }
    }

    /**
     * Suspicious activity: alerts per severity.
     */
    public Map<String, Integer> getAlertCountsBySeverity(Connection conn) throws Exception {
        String sql = "SELECT severity, COUNT(*) AS cnt FROM alerts GROUP BY severity";
        try (PreparedStatement ps = conn.prepareStatement(sql); ResultSet rs = ps.executeQuery()) {
            Map<String, Integer> m = new LinkedHashMap<>();
            while (rs.next()) {
                m.put(rs.getString("severity"), rs.getInt("cnt"));
            }
            return m;
        }
    }

    /**
     * Top malicious IPs by number of critical alerts.
     */
    public Map<String, Integer> getTopMaliciousIPs(Connection conn, int limit) throws Exception {
        String sql = "SELECT source_ip, COUNT(*) AS cnt FROM alerts "
                + "WHERE severity = 'Critical' GROUP BY source_ip ORDER BY cnt DESC LIMIT ?";
        try (PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setInt(1, limit);
            try (ResultSet rs = ps.executeQuery()) {
                Map<String, Integer> m = new LinkedHashMap<>();
                while (rs.next()) {
                    m.put(rs.getString("source_ip"), rs.getInt("cnt"));
                }
                return m;
            }
        }
    }

    /**
     * Anomaly detection counts by anomaly type.
     */
    public Map<String, Integer> getAnomalyCounts(Connection conn) throws Exception {
        String sql = "SELECT anomaly_type, COUNT(*) AS cnt FROM anomalies GROUP BY anomaly_type";
        try (PreparedStatement ps = conn.prepareStatement(sql); ResultSet rs = ps.executeQuery()) {
            Map<String, Integer> m = new LinkedHashMap<>();
            while (rs.next()) {
                m.put(rs.getString("anomaly_type"), rs.getInt("cnt"));
            }
            return m;
        }
    }
}
