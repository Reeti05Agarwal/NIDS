package com.network.security.Dao.Detection;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import com.network.security.Intrusion_detection.InsiderThreatDetector;

public class InsiderThreatDao {
    private InsiderThreatDetector insiderThreatDetector;

    // Insert a new brute force detection rule into the database

    // Load the brute force detection thresholds from the database
    private void loadInsiderThreatDetector(Connection conn) {
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

    // update 


    // delete
}
