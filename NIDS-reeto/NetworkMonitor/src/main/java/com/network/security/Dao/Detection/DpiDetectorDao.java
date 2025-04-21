package com.network.security.Dao.Detection;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.network.security.Intrusion_detection.DpiDetector;

public class DpiDetectorDao {
    private DpiDetector dpiDetector;

    // Insert a new brute force detection rule into the database
    public void insertDpiDetector(Connection conn) {
        String sql = "INSERT INTO dpi_keywords (keyword) VALUES (?)";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, dpiDetector.getKeyword());
                stmt.executeUpdate();
            } catch (SQLException e) {
                Logger.getLogger(DpiDetectorDao.class.getName()).log(Level.SEVERE, "[ERROR] Failed to insert DPI detection rule", e);
                System.err.println("[ERROR] Failed to insert DPI detection rule");
                e.printStackTrace();
        }
    }

    // Load the brute force detection thresholds from the database
    public void loadDpiDetector(Connection conn) {
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
