package com.network.security.util;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

public class MYSQLconnection {
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
}
