package com.network.security.Dao.Detection;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import com.network.security.Intrusion_detection.ExtICMPDetection;

public class ExtICMPDao {
    private ExtICMPDetection extICMPDetection;

    

    // Insert a new brute force detection rule into the database
    public void insertExtICMPDetection(Connection conn) {
        String sql = "INSERT INTO external_icmp_block (source_ip) VALUES (?)";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, extICMPDetection.getExticmpIPAddress());
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to insert brute force detection rule");
            e.printStackTrace();
        }
    }

    // Load the brute force detection thresholds from the database
    public void loadBruteForceThresholds(Connection conn) {
        List<String> ipList = new ArrayList<>();
        String sql = "SELECT source_ip FROM external_icmp_block ";
        try (PreparedStatement stmt = conn.prepareStatement(sql);
             ResultSet rs = stmt.executeQuery()) {

            while (rs.next()) {
                ipList.add(rs.getString("source_ip"));
            }
            extICMPDetection.setExticmpIPAddress(ipList);

        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to load brute force thresholds");
            e.printStackTrace();
        }
    }

    // update 
    public void updateExtICMPDetection(Connection conn, String newIPAddress, int id) {
        String sql = "UPDATE external_icmp_block SET source_ip = ? WHERE id = ?";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setString(1, newIPAddress);
            stmt.setInt(2, id);
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to update brute force detection rule");
            e.printStackTrace();
        }
    }


    // delete
    public void deleteExtICMPDetection(Connection conn, int id) {
        String sql = "DELETE FROM external_icmp_block WHERE id = ?";
        try (PreparedStatement stmt = conn.prepareStatement(sql)) {
            stmt.setInt(1, id);
            stmt.executeUpdate();
        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to delete brute force detection rule");
            e.printStackTrace();
        }
    }
}
