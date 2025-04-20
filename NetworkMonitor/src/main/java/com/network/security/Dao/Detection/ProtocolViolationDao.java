package com.network.security.Dao.Detection;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import com.network.security.Intrusion_detection.ProtocolViolationDetection;

public class ProtocolViolationDao {
    private ProtocolViolationDetection protocolViolationDetection;

    // Insert a new brute force detection rule into the database

    // Load the brute force detection thresholds from the database
    public void loadProtocolViolation(Connection conn) {
        String sql = "SELECT protocol_name, port FROM restricted_protocols";
        try (PreparedStatement stmt = conn.prepareStatement(sql);
             ResultSet rs = stmt.executeQuery()) {

            while (rs.next()) {
                protocolViolationDetection.setPVProtocolName(rs.getString("protocol_name"));
                protocolViolationDetection.setPVPort(rs.getInt("port"));
            }

        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to load brute force thresholds");
            e.printStackTrace();
        }
    }

    // update 


    // delete
}
