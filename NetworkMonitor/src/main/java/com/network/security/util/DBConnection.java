package com.network.security.util;

import java.io.IOException;
import java.io.InputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.util.Properties;

public class DBConnection {

    private static final Properties cfg = new Properties();

    static {
        // Load config.properties from classpath
        try (InputStream in = DBConnection.class
                .getClassLoader()
                .getResourceAsStream("config.properties")) {
            if (in == null) {
                throw new IOException("config.properties not found on classpath");
            }
            cfg.load(in);

            // Register the JDBC driver
            String driver = cfg.getProperty("db.driver");
            if (driver == null || driver.isBlank()) {
                throw new IllegalStateException("db.driver not set in config.properties");
            }
            Class.forName(driver);

        } catch (IOException | ClassNotFoundException | IllegalStateException e) {
            throw new ExceptionInInitializerError("Failed to load DB config: " + e.getMessage());
        }
    }

    public static Connection getConnection() throws Exception {
        return DriverManager.getConnection(
                cfg.getProperty("db.url"),
                cfg.getProperty("db.user"),
                cfg.getProperty("db.password")
        );
    }
}
