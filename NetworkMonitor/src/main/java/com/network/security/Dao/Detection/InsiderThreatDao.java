package com.network.security.Dao.Detection;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import com.network.security.Intrusion_detection.InsiderThreatDetector;

public class InsiderThreatDao {
    private InsiderThreatDetector insiderThreatDetector;

    // Insert a new brute force detection rule into the database
    public void insertInsiderThreatRule(Connection conn) {
        String sql = "INSERT INTO insider_threat_rules (access_threshold, time_window_sec) VALUES (?, ?)";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, insiderThreatDetector.getInsiderPacketThreshold());
            stmt.setInt(2, insiderThreatDetector.getInsiderTimeWindow());
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to insert brute force detection rule");
            e.printStackTrace();
        }
    }

    // Load the brute force detection thresholds from the database
    public void loadInsiderThreatDetector(Connection conn) {
        String sql = "SELECT access_threshold, time_window_sec FROM insider_threat_rules ";
        try (PreparedStatement stmt = conn.prepareStatement(sql);
             ResultSet rs = stmt.executeQuery()) {

            while (rs.next()) {
                insiderThreatDetector.setInsiderPacketThreshold(rs.getInt("access_threshold"));
                insiderThreatDetector.setInsiderTimeWindow(rs.getInt("time_window_sec"));
            }

        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to load brute force thresholds");
            e.printStackTrace();
        }
    }

    // update threshold
    public void updateInsiderPacketThreshold(Connection conn, int newPacketThreshold, int id) {
        String sql = "UPDATE insider_threat_rules SET access_threshold = ? WHERE id = ?";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, newPacketThreshold);
            stmt.setInt(2, id);
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to update insider threat detection rule");
            e.printStackTrace();
        }
    }

    // update time window
    public void updateInsiderTimeWindow(Connection conn, int newTimeWindow, int id) {
        String sql = "UPDATE insider_threat_rules SET time_window_sec = ? WHERE id = ?";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, newTimeWindow);
            stmt.setInt(2, id);
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to update insider threat detection rule");
            e.printStackTrace();
        }
    }


    // delete
    public void deleteInsiderThreatRule(Connection conn, int id) {
        String sql = "DELETE FROM insider_threat_rules WHERE id = ?";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, id);
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to delete insider threat detection rule");
            e.printStackTrace();
        }
    }

}
