package com.network.security.Dao;

import java.sql.*;
import java.util.logging.Level;
import java.util.logging.Logger;

public class AlertDao {

    // Insert a new alert into the database
    public void insertAlert(Connection conn, String sourceIp, String destinationIp, String protocol,
                            int ruleId, String severity, String alertMessage) {

        String sql = "INSERT INTO alerts (source_ip, destination_ip, protocol, rule_id, severity, alert_message) " +
                     "VALUES (?, ?, ?, ?, ?, ?)";

        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, sourceIp);
            stmt.setString(2, destinationIp);
            stmt.setString(3, protocol);
            stmt.setInt(4, ruleId);
            stmt.setString(5, severity);
            stmt.setString(6, alertMessage);

            stmt.executeUpdate();
            System.out.println("[INFO] Alert inserted successfully.");

        } catch (SQLException e) {
            Logger.getLogger(AlertDao.class.getName()).log(Level.SEVERE, "[ERROR] Failed to insert alert", e);
        }
    }

    // Fetch and display all alerts
    public void getAllAlerts(Connection conn) {
        String sql = "SELECT * FROM alerts ORDER BY timestamp DESC";

        try (PreparedStatement stmt = conn.prepareStatement(sql);
             ResultSet rs = stmt.executeQuery()) {

            System.out.println("---- Alert Log ----");
            while (rs.next()) {
                int alertId = rs.getInt("alert_id");
                Timestamp timestamp = rs.getTimestamp("timestamp");
                String sourceIp = rs.getString("source_ip");
                String destinationIp = rs.getString("destination_ip");
                String protocol = rs.getString("protocol");
                int ruleId = rs.getInt("rule_id");
                String severity = rs.getString("severity");
                String message = rs.getString("alert_message");

                System.out.printf("[%s] ID:%d | Severity:%s | %s -> %s | Protocol:%s | Rule:%d\nMessage: %s\n\n",
                        timestamp, alertId, severity, sourceIp, destinationIp, protocol, ruleId, message);
            }

        } catch (SQLException e) {
            Logger.getLogger(AlertDao.class.getName()).log(Level.SEVERE, "[ERROR] Failed to fetch alerts", e);
        }
    }
}