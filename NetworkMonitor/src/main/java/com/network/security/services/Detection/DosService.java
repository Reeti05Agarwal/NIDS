package com.network.security.services.Detection;

public class DosService {
    package com.network.security.Service;

import com.network.security.Dao.Detection.DoSDetectorDao;
import com.network.security.Intrusion_detection.DoSDetector;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class DoSDetectorService {
    private DoSDetectorDao dao;
    private DoSDetector detector;

    public DoSDetectorService(int threshold, int timeWindow) {
        this.detector = new DoSDetector(threshold, timeWindow);
        this.dao = new DoSDetectorDao();
    }

    // Example method to analyze packet count and time
    public boolean analyzeTraffic(int packetCount, int secondsElapsed) {
        return detector.detect(packetCount, secondsElapsed);
    }

    // Insert detection rule into DB
    public void saveRuleToDatabase() {
        try (Connection conn = getConnection()) {
            dao.setDetector(detector); // provide detector instance to DAO
            dao.insertDoSDetector(conn);
        } catch (SQLException e) {
            System.err.println("[ERROR] DB connection failed while inserting rule");
            e.printStackTrace();
        }
    }

    // Load rule from DB and update detector object
    public void loadRuleFromDatabase() {
        try (Connection conn = getConnection()) {
            dao.setDetector(detector);
            dao.loadDoSDetector(conn);
        } catch (SQLException e) {
            System.err.println("[ERROR] DB connection failed while loading rule");
            e.printStackTrace();
        }
    }

    // Update attack type
    public void updateAttackType(String newType, int id) {
        try (Connection conn = getConnection()) {
            dao.updateDoSAttackType(conn, newType, id);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // Update threshold
    public void updateThreshold(int newThreshold, int id) {
        try (Connection conn = getConnection()) {
            dao.updateDoSPacketThreshold(conn, newThreshold, id);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // Update time window
    public void updateTimeWindow(int newWindow, int id) {
        try (Connection conn = getConnection()) {
            dao.updateDoSTimeWindow(conn, newWindow, id);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // Delete rule by ID
    public void deleteRule(int id) {
        try (Connection conn = getConnection()) {
            dao.deleteDoSRule(conn, id);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    private Connection getConnection() throws SQLException {
        String url = "jdbc:mysql://localhost:3306/network_security"; // Update with your DB details
        String user = "root";
        String pass = "password";
        return DriverManager.getConnection(url, user, pass);
    }

    public DoSDetector getDetector() {
        return detector;
    }
}

