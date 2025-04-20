package com.network.security.Dao.Detection;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import com.network.security.Intrusion_detection.ExtICMPDetection;

public class ExtICMPDao {
    private ExtICMPDetection extICMPDetection;

    // Insert a new brute force detection rule into the database

    // Load the brute force detection thresholds from the database
    private void loadBruteForceThresholds(Connection conn) {
        String sql = "SELECT source_ip FROM external_icmp_block ";
        try (PreparedStatement stmt = conn.prepareStatement(sql);
             ResultSet rs = stmt.executeQuery()) {

            while (rs.next()) {
                extICMPDetection.setExticmpIPAddress(rs.getString("source_ip"));
             }

        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to load brute force thresholds");
            e.printStackTrace();
        }
    }

    // update 


    // delete
}
