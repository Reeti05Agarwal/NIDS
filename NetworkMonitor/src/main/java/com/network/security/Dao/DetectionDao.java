package com.network.security.Dao;

import java.io.FileInputStream;
import java.io.IOException;
import java.sql.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class DetectionDao {

    // Configuration loader
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

    // Threshold-based rule data
    protected final Map<String, Integer> thresholdMap = new ConcurrentHashMap<>();
    protected final Map<String, Integer> timeWindowMap = new ConcurrentHashMap<>();
    // Pattern-based rule data (rule name -> set of matching values)
    protected final Map<String, Set<String>> patternMap = new ConcurrentHashMap<>();

    // Load all rule types
    public void loadAllRules(Connection conn) {
        loadBruteForceThresholds(conn);
        loadBlacklistedDomains(conn);
        loadSuspiciousUserAgents(conn);
        // Add more loaders here
    }

    // Threshold-based loader for brute force 
    private void loadBruteForceThresholds(Connection conn) {
        String sql = "SELECT rule_name, failed_attempt_threshold, time_window_sec FROM view_brute_force_rules";
        try (PreparedStatement stmt = conn.prepareStatement(sql);
             ResultSet rs = stmt.executeQuery()) {

            while (rs.next()) {
                String rule = rs.getString("rule_name");
                int threshold = rs.getInt("failed_attempt_threshold");
                int window = rs.getInt("time_window_sec");

                thresholdMap.put(rule, threshold);
                timeWindowMap.put(rule, window);
            }

        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to load brute force thresholds");
            e.printStackTrace();
        }
    }

    // blacklisted domains 
    private void loadBlacklistedDomains(Connection conn) {
        String sql = "SELECT rule_name, domain FROM view_block_blacklisted_domains"; // this view must exist
        try (PreparedStatement stmt = conn.prepareStatement(sql);
             ResultSet rs = stmt.executeQuery()) {

            while (rs.next()) {
                String rule = rs.getString("rule_name");
                String domain = rs.getString("domain");

                patternMap.computeIfAbsent(rule, k -> new HashSet<>()).add(domain);
            }

        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to load blacklisted domains");
            e.printStackTrace();
        }
    }

    //suspicious user agents 
    private void loadSuspiciousUserAgents(Connection conn) {
        String sql = "SELECT rule_name, user_agent FROM view_detect_suspicious_user_agents"; // another view
        try (PreparedStatement stmt = conn.prepareStatement(sql);
             ResultSet rs = stmt.executeQuery()) {

            while (rs.next()) {
                String rule = rs.getString("rule_name");
                String userAgent = rs.getString("user_agent");

                patternMap.computeIfAbsent(rule, k -> new HashSet<>()).add(userAgent);
            }

        } catch (SQLException e) {
            System.err.println("[ERROR] Failed to load suspicious user agents");
            e.printStackTrace();
        }
    }

    
}
