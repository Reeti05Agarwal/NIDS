// src/main/java/com/network/security/dao/LogDao.java
package com.network.security.Dao;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import com.network.security.entity.LogEntry;
import com.network.security.util.DBConnection;

public class LogDao {

    /**
     * Inserts a new log entry (e.g. LOGIN or LOGOUT).
     */
    public void insertLog(String username, String role, String event) {
        String sql = "INSERT INTO user_logs(username, role, event) VALUES (?, ?, ?)";
        try (Connection conn = DBConnection.getConnection(); PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setString(1, username);
            ps.setString(2, role);
            ps.setString(3, event);
            ps.executeUpdate();

        } catch (SQLException e) {
            throw new RuntimeException("Failed to insert log", e);
        }
    }

    /**
     * Fetches all log entries, newest first.
     */
    public List<LogEntry> getAllLogs() {
        List<LogEntry> logs = new ArrayList<>();
        String sql = "SELECT id, username, role, event, event_time FROM user_logs ORDER BY event_time DESC";
        try (Connection conn = DBConnection.getConnection(); PreparedStatement ps = conn.prepareStatement(sql); ResultSet rs = ps.executeQuery()) {

            while (rs.next()) {
                logs.add(new LogEntry(
                        rs.getInt("id"),
                        rs.getString("username"),
                        rs.getString("role"),
                        rs.getString("event"),
                        rs.getTimestamp("event_time")
                ));
            }
        } catch (SQLException e) {
            throw new RuntimeException("Failed to fetch logs", e);
        }
        return logs;
    }
}
