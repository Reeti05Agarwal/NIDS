package com.network.security.Dao.Detection;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import com.network.security.Intrusion_detection.DNSWebFilterDetector;

public class DNSWebFilterDao {
    private DNSWebFilterDetector dnsWebFilterDetector;

    // Insert a new brute force detection rule into the database

    // Load the brute force detection thresholds from the database
    private void loadBruteForceThresholds(Connection conn) {
        String sql = "SELECT failed_attempt_threshold, time_window_sec FROM view_brute_force_rules";
        try (PreparedStatement stmt = conn.prepareStatement(sql);
             ResultSet rs = stmt.executeQuery()) {

            while (rs.next()) {
                dnsWebFilterDetector.setDNSWebFilterDetector(rs.getInt("failed_attempt_threshold"));
                dnsWebFilterDetector.setDNSWebFilterDetector(rs.getInt("time_window_sec"));
            }

        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to load brute force thresholds");
            e.printStackTrace();
        }
    }

    // update 


    // delete
}
