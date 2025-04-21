package com.network.security.Dao.Detection;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import com.network.security.Intrusion_detection.DNSWebFilterDetector;

public class DNSWebFilterDao {
    private DNSWebFilterDetector dnsWebFilterDetector;

    // Insert a new brute force detection rule into the database
    public void insertDnsWebFilterRule(Connection conn, String pattern, int threshold, int timeWindow) {
        String sql = "INSERT INTO dns_web_filtering_rules (pattern, threshold, time_window_seconds) VALUES (?, ?, ?)";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, pattern);
            stmt.setInt(2, threshold);
            stmt.setInt(3, timeWindow);
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to insert DNS web filter rule");
            e.printStackTrace();
        }
    }

    // Load the brute force detection thresholds from the database
    public void loadDnsWebFilterThreshold(Connection conn, String pattern) {
        String sql = "SELECT pattern, threshold, time_window_seconds FROM dns_web_filtering_rules WHERE pattern = ?";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, pattern);
            ResultSet rs = stmt.executeQuery();

            while (rs.next()) {
                dnsWebFilterDetector.setDnsWebFilterPattern(rs.getString("pattern"));
                dnsWebFilterDetector.setDnsWebFilterThreshold(rs.getInt("threshold"));
                dnsWebFilterDetector.setDnsWebFilterTimeWindow(rs.getInt("time_window_seconds"));
            }

        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to load DNS web filter thresholds");
            e.printStackTrace();
        }
    }

    // update threshold
    public void updateDnsWebFilterThreshold(Connection conn, int newThreshold, int id) {
        String sql = "UPDATE dns_web_filtering_rules SET threshold = ? WHERE id = ?";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, newThreshold);
            stmt.setInt(2, id);
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to update DNS web filter threshold");
            e.printStackTrace();
        }
    }

    // update time window
    public void updateDnsWebFilterTimeWindow(Connection conn, int newTimeWindow, int id) {
        String sql = "UPDATE dns_web_filtering_rules SET time_window_seconds = ? WHERE id = ?";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, newTimeWindow);
            stmt.setInt(2, id);
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to update DNS web filter time window");
            e.printStackTrace();
        }
    }


    // delete
    public void deleteDnsWebFilterRule(Connection conn, int id) {
        String sql = "DELETE FROM dns_web_filtering_rules WHERE id = ?";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, id);
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to delete DNS web filter rule");
            e.printStackTrace();
        }
    }
}
