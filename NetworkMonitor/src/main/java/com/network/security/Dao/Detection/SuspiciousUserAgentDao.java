package com.network.security.Dao.Detection;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import com.network.security.Intrusion_detection.SuspiciousUserAgentDetection;

public class SuspiciousUserAgentDao {
    private SuspiciousUserAgentDetection suspiciousUserAgentDetection;

    // Insert a new brute force detection rule into the database

    // Load the brute force detection thresholds from the database
    private void loadSuspiciousUserAgent(Connection conn) {
        String sql = "SELECT user_agent FROM suspicious_user_agents";
        try (PreparedStatement stmt = conn.prepareStatement(sql);
             ResultSet rs = stmt.executeQuery()) {

            while (rs.next()) {
                suspiciousUserAgentDetection.setSudKeyword(rs.getString("user_agent"));
             }

        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to load brute force thresholds");
            e.printStackTrace();
        }
    }

    // update 


    // delete
}
