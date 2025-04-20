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
    private void loadDnsWebFilterThreshold(Connection conn) {
        String sql = "SELECT pattern, threshold, time_window_seconds FROM dns_web_filtering_rules ";
        try (PreparedStatement stmt = conn.prepareStatement(sql);
             ResultSet rs = stmt.executeQuery()) {

            while (rs.next()) {
                dnsWebFilterDetector.setDnsWebFilterPattern(rs.getString("pattern"));
                dnsWebFilterDetector.setDnsWebFilterThreshold(rs.getInt("threshold"));
                dnsWebFilterDetector.setDnsWebFilterTimeWindow(rs.getInt("time_window_seconds"));
            }

        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to load brute force thresholds");
            e.printStackTrace();
        }
    }

    // update 


    // delete
}
