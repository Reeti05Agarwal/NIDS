package com.network.security.Dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * DAO for alert CRUD operations with adaptive column support.
 */
public class AlertDao {

    private static final Logger LOG = Logger.getLogger(AlertDao.class.getName());

    /**
     * Inserts a new alert into the database.
     */
    public void insertAlert(Connection conn,
            String sourceIp,
            String destinationIp,
            String protocol,
            int ruleId,
            String severity,
            String alertMessage) {
        String sql = "INSERT INTO alerts "
                + "(source_ip, destination_ip, protocol, rule_id, severity, alert_message) "
                + "VALUES (?, ?, ?, ?, ?, ?)";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, sourceIp);
            stmt.setString(2, destinationIp);
            stmt.setString(3, protocol);
            stmt.setInt(4, ruleId);
            stmt.setString(5, severity);
            stmt.setString(6, alertMessage);
            stmt.executeUpdate();
        } catch (SQLException e) {
            LOG.log(Level.SEVERE, "[ERROR] Failed to insert alert", e);
        }
    }

    /**
     * Fetches and prints all alerts, introspecting the table for whatever
     * column names exist, so you won’t get SQLExceptions if your schema uses
     * slightly different names.
     */
    public void getAllAlerts(Connection conn) {
        String sql = "SELECT * FROM alerts ORDER BY timestamp DESC";
        try (PreparedStatement stmt = conn.prepareStatement(sql); ResultSet rs = stmt.executeQuery()) {

            // Inspect the result‑set metadata once
            ResultSetMetaData meta = rs.getMetaData();
            String cAlertId = findColumn(meta, "alert_id", "id");
            String cTime = findColumn(meta, "timestamp", "time");
            String cSource = findColumn(meta, "source_ip", "src_ip", "sourceip", "srcip");
            String cDest = findColumn(meta, "destination_ip", "dest_ip", "dst_ip", "dstip");
            String cProtocol = findColumn(meta, "protocol");
            String cRule = findColumn(meta, "rule_id", "ruleid");
            String cSeverity = findColumn(meta, "severity");
            String cMessage = findColumn(meta, "alert_message", "message", "alertmessage");

            System.out.println("---- Alert Log ----");
            while (rs.next()) {
                String id = cAlertId != null ? rs.getString(cAlertId) : "";
                String time = cTime != null ? rs.getString(cTime) : "";
                String src = cSource != null ? rs.getString(cSource) : "";
                String dst = cDest != null ? rs.getString(cDest) : "";
                String proto = cProtocol != null ? rs.getString(cProtocol) : "";
                String rule = cRule != null ? rs.getString(cRule) : "";
                String sev = cSeverity != null ? rs.getString(cSeverity) : "";
                String msg = cMessage != null ? rs.getString(cMessage) : "";

                System.out.printf(
                        "[%s] ID:%s | Severity:%s | %s -> %s | Protocol:%s | Rule:%s%n"
                        + "Message: %s%n%n",
                        time, id, sev, src, dst, proto, rule, msg
                );
            }

        } catch (SQLException e) {
            LOG.log(Level.SEVERE, "[ERROR] Failed to fetch alerts", e);
        }
    }

    /**
     * Scans the ResultSetMetaData for the first column whose name matches any
     * of the provided candidates (case‑insensitive).
     */
    private String findColumn(ResultSetMetaData meta, String... candidates) throws SQLException {
        int columnCount = meta.getColumnCount();
        for (String cand : candidates) {
            for (int i = 1; i <= columnCount; i++) {
                if (meta.getColumnName(i).equalsIgnoreCase(cand)) {
                    return meta.getColumnName(i);
                }
            }
        }
        return null;
    }
}
