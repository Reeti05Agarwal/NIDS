package com.network.security.Dao;

import java.io.FileInputStream;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Map;
import java.util.Properties;

/*
 * UI
 * 
 * 
 * Detections:
 * 
 * 
 */

public class DetectionDao {
    private static final String DB_URL = "jdbc:mysql://localhost:3306/network";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "Maria@mysql05";

    public static Properties loadConfig(String filePath) {
        Properties properties = new Properties();
        try (FileInputStream input = new FileInputStream(filePath)) {
            properties.load(input);
        } catch (IOException e) {
            System.err.println("[ERROR] Could not load config file: " + filePath);
            e.printStackTrace();
        }
        return properties;
    } 

    public static void restrictedProtocols(Map<String, Object> data) {
    if (data.isEmpty()) {
        System.err.println("[ERROR] Skipping invalid packet...");
        return;
    }

    try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
        String selectQuery = "SELECT PROTOCOLNAME FROM RESTRICTED_PROTOCOLS WHERE PROTOCOLNAME = ?";
        PreparedStatement stmt = conn.prepareStatement(selectQuery);
        stmt.setString(1, (String) data.get("PROTOCOLNAME"));
        
        ResultSet rs = stmt.executeQuery();
        
        if (rs.next()) {
            // Protocol is restricted
            System.out.println("[ALERT] Restricted protocol detected: " + rs.getString("PROTOCOLNAME"));
            // You can take action here, like logging, alerting, or dropping the packet.
        }
        
        rs.close();
        stmt.close();
    } catch (SQLException e) {
        e.printStackTrace();
    }
}




    static void EdittingThreshold(Map<String, Object> threshold) {
        if (threshold.isEmpty()) {
            System.err.println("[ERROR] Skipping invalid packet...");
            return;
        }

        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            // Super Table: Packet Metadata
            String updateQuery_threshold = "INSERT INTO User (Username, Password, Role) VALUES (?, ?, ?)"; 
            PreparedStatement stmt_threshold = conn.prepareStatement(updateQuery_threshold);
            
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    static void GetDetection(Map<String, Object> DetectionData) {
        if (DetectionData.isEmpty()) {
            System.err.println("[ERROR] Skipping invalid packet...");
            return;
        }

        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            // Super Table: Packet Metadata
            String updateQuery_threshold = "SELECT INTO User (ID, DETECTION_NAME, DESCRIPTION, THRESHOLD, UPDATE_DATE) VALUES (?, ?, ?, ?, ?)"; 
            PreparedStatement stmt_threshold = conn.prepareStatement(updateQuery_threshold);
            stmt_threshold.setInt(1, (Integer) DetectionData.get("ID"));
             
             
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }




}
