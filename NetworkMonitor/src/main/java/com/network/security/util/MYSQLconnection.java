package com.network.security.util;

import java.io.FileInputStream;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;

public class MYSQLconnection {
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


     public static Connection getConnection() {
        try {
            // Optional: Load driver class (modern JDBC may not require this)
            Class.forName("com.mysql.cj.jdbc.Driver"); 
            return DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
        } catch (ClassNotFoundException | SQLException e) {
            System.err.println("[ERROR] Failed to connect to database");
            e.printStackTrace();
            return null;
        }
    }
}
