package com.network.security.Dao.Detection;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import com.network.security.Intrusion_detection.DpiDetector;

public class DpiDetectorDao {
    private DpiDetector dpiDetector;

    // Insert a new brute force detection rule into the database

    // Load the brute force detection thresholds from the database
    private void loadDpiDetector(Connection conn) {
        String sql = "SELECT keyword FROM dpi_keywords ";
        try (PreparedStatement stmt = conn.prepareStatement(sql);
             ResultSet rs = stmt.executeQuery()) {

            while (rs.next()) {
                dpiDetector.setKeyword(rs.getString("keyword"));
             }

        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to load brute force thresholds");
            e.printStackTrace();
        }
    }

    // update 


    // delete
}
