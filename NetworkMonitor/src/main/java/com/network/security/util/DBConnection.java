package com.network.security.util;

import java.io.FileInputStream;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;

public class DBConnection {

    private static final String CONFIG_FILE_PATH = "NetworkMonitor/src/main/resources/configs/config.properties";  // Update path as needed

    public static Properties loadConfig() {
        Properties properties = new Properties();
        try (FileInputStream input = new FileInputStream(CONFIG_FILE_PATH)) {
            properties.load(input);
        } catch (IOException e) {
            System.err.println("[ERROR] Could not load config file: " + CONFIG_FILE_PATH);
            e.printStackTrace();
        }
        return properties;
    }

    public static Connection getConnection() {
        Properties config = loadConfig();  // ✅ Now it's declared
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            String dbUrl = config.getProperty("db.url");
            String dbUser = config.getProperty("db.user");
            String dbPassword = config.getProperty("db.password");
            return DriverManager.getConnection(dbUrl, dbUser, dbPassword);
        } catch (ClassNotFoundException | SQLException e) {
            System.err.println("[ERROR] Failed to connect to database");
            e.printStackTrace();
            return null;
        }
    }
}
