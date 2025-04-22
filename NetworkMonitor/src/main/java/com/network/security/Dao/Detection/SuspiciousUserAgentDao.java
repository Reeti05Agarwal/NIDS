package com.network.security.Dao.Detection;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import com.network.security.Intrusion_detection.SuspiciousUserAgentDetection;

public class SuspiciousUserAgentDao {
    private SuspiciousUserAgentDetection suspiciousUserAgentDetection;

    // Insert a new brute force detection rule into the database
    public void insertSuspiciousUserAgent(Connection conn) {
        String sql = "INSERT INTO suspicious_user_agents (user_agent) VALUES (?)";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            for (String userAgent : suspiciousUserAgentDetection.getSudKeyword()) {
                stmt.setString(1, userAgent);
                stmt.executeUpdate();
            }
        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to insert brute force detection rule");
            e.printStackTrace();
        }
    }

    // Load the brute force detection thresholds from the database
    public void loadSuspiciousUserAgent(Connection conn) {
        List<String> agents = new ArrayList<>();
        String sql = "SELECT user_agent, severity FROM suspicious_user_agents";
        try (PreparedStatement stmt = conn.prepareStatement(sql);
             ResultSet rs = stmt.executeQuery()) {

            while (rs.next()) {
                agents.add(rs.getString("user_agent"));
            }
            suspiciousUserAgentDetection.setSudKeyword(agents);
            suspiciousUserAgentDetection.setSeverity(rs.getString("severity"));
            System.out.println("[DAO SUS USER AGENT] Thresholds loaded");

        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to load brute force thresholds");
            e.printStackTrace();
        }
    }

    // update 
    public void updateSuspiciousUserAgent(Connection conn, String newUserAgent, int id) {
        String sql = "UPDATE suspicious_user_agents SET user_agent = ? WHERE id = ?";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, newUserAgent);
            stmt.setInt(2, id);
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to update brute force detection rule");
            e.printStackTrace();
        }
    }


    // delete
    public void deleteSuspiciousUserAgent(Connection conn, int id) {
        String sql = "DELETE FROM suspicious_user_agents WHERE id = ?";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, id);
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to delete suspicious user agent rule");
            e.printStackTrace();
        }
    }

}
