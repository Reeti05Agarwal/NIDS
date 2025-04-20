package com.network.security.Dao.Detection;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import com.network.security.Intrusion_detection.DoSDetector;

public class DoSDetectorDao {
    private DoSDetector doSDetector;

    // Insert a new brute force detection rule into the database

    // Load the brute force detection thresholds from the database
    private void loadDoSDetector(Connection conn) {
        String sql = "SELECT attack_type, packet_threshold, time_window_sec FROM ddos_rules";
        try (PreparedStatement stmt = conn.prepareStatement(sql);
             ResultSet rs = stmt.executeQuery()) {

            while (rs.next()) {
                doSDetector.setDosAttackType(rs.getString("attack_type"));
                doSDetector.setDosPacketThreshold(rs.getInt("packet_threshold"));
                doSDetector.setDosTimeWindow(rs.getInt("time_window_sec"));
            }

        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to load brute force thresholds");
            e.printStackTrace();
        }
    }

    // update 


    // delete
}
