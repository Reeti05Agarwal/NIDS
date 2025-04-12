package com.network.security.Dao;

import java.io.FileInputStream;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.Map;
import java.util.Properties;

public class DetectionDao {
    static Properties config = loadConfig("NetworkMonitor\\src\\main\\resources\\config.properties");
    private static final String DB_URL = config.getProperty("db.url");
    private static final String DB_USER = config.getProperty("db.user");
    private static final String DB_PASSWORD = config.getProperty("db.password");

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


    static void EdittingThreshold(Map<String, Object> threshold) {
        if (UserData.isEmpty()) {
            System.err.println("[ERROR] Skipping invalid packet...");
            return;
        }

        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            // Super Table: Packet Metadata
            String insertQuery_NewUser = "INSERT INTO User (Username, Password, Role) VALUES (?, ?, ?)"; 
            PreparedStatement stmt_NewUser = conn.prepareStatement(insertQuery_NewUser);
            stmt_NewUser.setString(1, (String) UserData.get("Username"));
            stmt_NewUser.setString(2, (String) UserData.get("Password"));
            stmt_NewUser.setString(3, (String) UserData.get("Role"));
             
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

}
