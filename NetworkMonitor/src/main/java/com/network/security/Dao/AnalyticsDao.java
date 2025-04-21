package com.network.security.Dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.LinkedHashMap;
import java.util.Map;

import com.network.security.util.DBConnection;

/**
 * Simple aggregates that feed MainFrame charts – Java‑14‑friendly.
 */
public class AnalyticsDao {

    public Map<String, Integer> topMaliciousIps(int limit) throws Exception {
        String sql
                = "SELECT source_ip, COUNT(*) AS hits "
                + "FROM alerts "
                + "GROUP BY source_ip "
                + "ORDER BY hits DESC "
                + "LIMIT ?";
        return queryToMap(sql, limit);
    }

    public Map<String, Integer> portActivity(int limit) throws Exception {
        String sql
                = "SELECT CAST(destPort AS CHAR), COUNT(*) AS cnt "
                + "FROM Transport_Layer "
                + "GROUP BY destPort "
                + "ORDER BY cnt DESC "
                + "LIMIT ?";
        return queryToMap(sql, limit);
    }

    public Map<String, Integer> attackedServices(int limit) throws Exception {
        String sql
                = "SELECT App_Protocol, COUNT(*) AS cnt "
                + "FROM Application_Layer "
                + "GROUP BY App_Protocol "
                + "ORDER BY cnt DESC "
                + "LIMIT ?";
        return queryToMap(sql, limit);
    }

    /* ---------- private helper ---------------------------------------- */
    private Map<String, Integer> queryToMap(String sql, int limit) throws Exception {
        Map<String, Integer> map = new LinkedHashMap<>();
        try (Connection c = DBConnection.getConnection(); PreparedStatement ps = c.prepareStatement(sql)) {

            ps.setInt(1, limit);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    map.put(rs.getString(1), rs.getInt(2));
                }
            }
        }
        return map;
    }
}
