package com.network.security.Dao;

import java.sql.*;
import java.util.HashMap;

public class ThresholdManager {

    private static HashMap<String, Integer> thresholdMap = new HashMap<>();

    // Define rule-to-table mapping + custom query
    private static final HashMap<String, String> thresholdQueries = new HashMap<String, String>() {{
        put("ddos", "SELECT packet_threshold FROM ddos_rules LIMIT 1");
        put("dpi", "SELECT payload_length_threshold FROM dpi_rules LIMIT 1");
        put("brute_force", "SELECT failed_attempt_threshold FROM brute_force_rules LIMIT 1");
        put("insider_threat", "SELECT access_threshold FROM insider_threat_rules LIMIT 1");
        put("dns_filter", "SELECT threshold FROM dns_web_filtering_rules LIMIT 1");
    }};

    public static void loadThresholds(Connection connection) {
        for (String ruleName : thresholdQueries.keySet()) {
            String query = thresholdQueries.get(ruleName);
            try (Statement stmt = connection.createStatement();
                 ResultSet rs = stmt.executeQuery(query)) {

                if (rs.next()) {
                    int threshold = rs.getInt(1);  // First column in SELECT
                    thresholdMap.put(ruleName, threshold);
                }

            } catch (SQLException e) {
                System.err.println("Error fetching threshold for " + ruleName + ": " + e.getMessage());
            }
        }

        System.out.println("Threshold map loaded: " + thresholdMap);
    }

    public static Integer getThreshold(String ruleName) {
        return thresholdMap.get(ruleName);
    }

    public static void updateThreshold(String ruleName, int newValue) {
        thresholdMap.put(ruleName, newValue);
        System.out.println("Updated threshold: " + ruleName + " = " + newValue);
    }

    public static void main(String[] args) {
        try {
            Connection connection = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/java", "user", "password"
            );// CHANGE ACCORDING TO YOUR DB
            loadThresholds(connection);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}