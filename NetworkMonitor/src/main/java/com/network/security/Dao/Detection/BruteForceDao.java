package com.network.security.Dao.Detection;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import com.network.security.Intrusion_detection.BruteForceDetector;

public class BruteForceDao {

    private BruteForceDetector bruteForceDetector;

    // Insert a new brute force detection rule into the database
    public void insertBruteForceRule(Connection conn, String service, int threshold, int timeWindow) {
        String sql = "INSERT INTO brute_force_rules (service, failed_attempt_threshold, time_window_sec) VALUES (?, ?, ?)";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, service);
            stmt.setInt(2, threshold);
            stmt.setInt(3, timeWindow);
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to insert brute force rule");
            e.printStackTrace();
        }
    }

    // Load the brute force detection thresholds from the database
    public void loadBruteForceThresholds(Connection conn, String service) {
        String sql = "SELECT failed_attempt_threshold, time_window_sec, severity FROM brute_force_rules where service = ?";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, service);
            ResultSet rs = stmt.executeQuery();

            while (rs.next()) {
                bruteForceDetector.setBrutePacketThreshold(rs.getInt("failed_attempt_threshold"));
                bruteForceDetector.setBruteTimeWindow(rs.getInt("time_window_sec"));
                bruteForceDetector.setSeverity(rs.getString("severity"));
            }

        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to load brute force thresholds");
            e.printStackTrace();
        }
    }

    // update threshold
    public void updateBruteForceThreshold(Connection conn, int newThreshold, int id) {
        String sql = "UPDATE brute_force_rules SET failed_attempt_threshold = ? WHERE id = ?";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, newThreshold);
            stmt.setInt(2, id);
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to update brute force threshold");
            e.printStackTrace();
        }
    }

    // update time window
    public void updateBruteForceTimeWindow(Connection conn, int newTimeWindow, int id) {
        String sql = "UPDATE brute_force_rules SET time_window_sec = ? WHERE id = ?";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, newTimeWindow);
            stmt.setInt(2, id);
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to update brute force time window");
            e.printStackTrace();
        }
    }

    // delete
    public void deleteBruteForceRule(Connection conn, int id) {
        String sql = "DELETE FROM brute_force_rules WHERE id = ?";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, id);
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to delete brute force rule");
            e.printStackTrace();
        }
    }
}
