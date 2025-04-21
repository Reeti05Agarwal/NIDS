package com.network.security.Dao.Detection;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import com.network.security.Intrusion_detection.DoSDetector;

public class DoSDetectorDao {
    private DoSDetector doSDetector;

    // Insert a new brute force detection rule into the database
    public void insertDoSDetector(Connection conn) {
        String sql = "INSERT INTO ddos_rules (attack_type, packet_threshold, time_window_sec) VALUES (?, ?, ?)";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, doSDetector.getDosAttackType());
            stmt.setInt(2, doSDetector.getDosPacketThreshold());
            stmt.setInt(3, doSDetector.getDosTimeWindow());

            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to insert brute force detection rule");
            e.printStackTrace();
        }
    }

    // Load the brute force detection thresholds from the database
    public void loadDoSDetector(Connection conn, String attackType) {
        String sql = "SELECT attack_type, packet_threshold, time_window_sec, severity FROM ddos_rules WHERE attack_type = ?";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, attackType);
            ResultSet rs = stmt.executeQuery();

            while (rs.next()) {
                doSDetector.setDosAttackType(rs.getString("attack_type"));
                doSDetector.setDosPacketThreshold(rs.getInt("packet_threshold"));
                doSDetector.setDosTimeWindow(rs.getInt("time_window_sec"));
                doSDetector.setSeverity(rs.getString("severity"));
            }

        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to load brute force thresholds");
            e.printStackTrace();
        }
    }

    // update Attack Type
    public void updateDoSAttackType(Connection conn, String newAttackType, int id) {
        String sql = "UPDATE ddos_rules SET attack_type = ? WHERE id = ?";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) { 
            stmt.setString(1, newAttackType);
            stmt.setInt(2, id);
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to update brute force detection rule");
            e.printStackTrace();
        }
    }

    // update Packet Threshold
    public void updateDoSPacketThreshold(Connection conn, int newPacketThreshold, int id) {
        String sql = "UPDATE ddos_rules SET packet_threshold = ? WHERE id = ?";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, newPacketThreshold);
            stmt.setInt(2, id);
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to update brute force detection rule");
            e.printStackTrace();
        }
    }
     

    // update Time Window
    public void updateDoSTimeWindow(Connection conn, int newTimeWindow, int id) {
        String sql = "UPDATE ddos_rules SET time_window_sec = ? WHERE id = ?";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, newTimeWindow);
            stmt.setInt(2, id);
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to update brute force detection rule");
            e.printStackTrace();
        }
    }
 

    // delete
    public void deleteDoSRule(Connection conn, int id) {
        String sql = "DELETE FROM ddos_rules WHERE id = ?";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, id);
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to delete brute force detection rule");
            e.printStackTrace();
        }
    }
}
