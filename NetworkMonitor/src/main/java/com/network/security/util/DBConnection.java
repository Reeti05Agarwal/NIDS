package com.network.security.util;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;

public class DBConnection {

    private static String dbUrl;
    private static String dbUser;
    private static String dbPass;

    // Make sure loadConfig returns the Properties
    public static Properties loadConfig() {
        Properties props = new Properties();
        try {
            // Use absolute path for debugging
            String absolutePath = "C:/Users/Reeti/Documents/nids/NetworkMonitor/config/config.properties";
            File configFile = new File(absolutePath); 
            FileInputStream fis = new FileInputStream(configFile);
            props.load(fis);
             

        } catch (IOException e) {
            System.err.println("[ERROR] Could not load config file: " + e.getMessage());
        }
        return props;  // Return the Properties object
    }
    

    public static Connection getConnection() {
        Properties config = loadConfig();  // Load config to get database details
        try {
            // Get database URL, user, and password from config file
            dbUrl = config.getProperty("db.url");
            dbUser = config.getProperty("db.username");
            dbPass = config.getProperty("db.password");
            
            // Ensure config properties are available
            if (dbUrl == null || dbUser == null || dbPass == null) {
                System.err.println("[ERROR] Missing database configuration.");
                return null;
            }

            // Load JDBC driver and establish connection
            Class.forName("com.mysql.cj.jdbc.Driver");
            return DriverManager.getConnection(dbUrl, dbUser, dbPass);
        } catch (ClassNotFoundException | SQLException e) {
            System.err.println("[ERROR] Failed to connect to database");
            e.printStackTrace();
            return null;
        }
    }
}
