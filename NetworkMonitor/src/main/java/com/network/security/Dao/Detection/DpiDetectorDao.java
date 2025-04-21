package com.network.security.Dao.Detection;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import com.network.security.Intrusion_detection.DpiDetector;

public class DpiDetectorDao {
    private DpiDetector dpiDetector;

    // Insert a new brute force detection rule into the database
    public void insertDpiDetector(Connection conn) {
        String sql = "INSERT INTO dpi_keywords (keyword) VALUES (?)";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            for (String keyword : dpiDetector.getKeyword()) {
                stmt.setString(1, keyword);
                stmt.executeUpdate();
            }
        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to insert DPI detection rule");
            e.printStackTrace();
        }
    }

    // Load the brute force detection thresholds from the database
    public void loadDpiDetector(Connection conn) {
        List<String> keywords_list = new ArrayList<>();
        String sql = "SELECT keyword, severity FROM dpi_keywords ";
        try (PreparedStatement stmt = conn.prepareStatement(sql);
             ResultSet rs = stmt.executeQuery()) {

            while (rs.next()) {
                keywords_list.add(rs.getString("keyword"));
            }
            dpiDetector.setKeyword(keywords_list);
            dpiDetector.setSeverity(rs.getString("severity"));

        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to load brute force thresholds");
            e.printStackTrace();
        }
    }

    // update 
    public void updateDpiDetector(Connection conn, String newKeyword, int id) {
        String sql = "UPDATE dpi_keywords SET keyword = ? WHERE id = ?";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, newKeyword);
            stmt.setInt(2, id);
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to update DPI detection rule");
            e.printStackTrace();
        }
    }


    // delete
    public void deleteDpiDetector(Connection conn, int id) {
        String sql = "DELETE FROM dpi_keywords WHERE id = ?";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, id);
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to delete DPI detection rule");
            e.printStackTrace();
        }
    }
}
