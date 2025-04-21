package com.network.security.Service.Detection;

import com.network.security.Dao.Detection.DpiDetectorDao;
import com.network.security.Intrusion_detection.DpiDetector;

import java.sql.Connection;
import java.sql.SQLException;

public class DpiService {
    private DpiDetectorDao dpiDetectorDao;
    private DpiDetector dpiDetector;

    public DpiService() {
        dpiDetectorDao = new DpiDetectorDao();
        dpiDetector = new DpiDetector(""); // Initializing with an empty keyword
    }

    // Insert a new DPI detection rule into the database
    public void insertDpiDetectionRule(Connection conn, String keyword) {
        dpiDetector.setKeyword(keyword);  // Set the keyword in the detector
        dpiDetectorDao.insertDpiDetector(conn);  // Insert the rule into the database
    }

    // Load DPI detection rule from the database
    public void loadDpiDetectionRule(Connection conn) {
        dpiDetectorDao.loadDpiDetector(conn);  // Load rule from database
    }

    // Update the DPI detection rule in the database
    public void updateDpiDetectionRule(Connection conn, String oldKeyword, String newKeyword) {
        dpiDetectorDao.updateDpiDetectorKeyword(conn, oldKeyword, newKeyword);
    }

    // Delete a DPI detection rule from the database
    public void deleteDpiDetectionRule(Connection conn, String keyword) {
        dpiDetectorDao.deleteDpiDetectorKeyword(conn, keyword);
    }

    // Detect DPI violation in a given content
    public boolean detectDpiViolation(String content) {
        return dpiDetector.detect(content);  // Use the DpiDetector to detect violations in the given content
    }

    // Getter and Setter for DpiDetector
    public DpiDetector getDpiDetector() {
        return dpiDetector;
    }

    public void setDpiDetector(DpiDetector dpiDetector) {
        this.dpiDetector = dpiDetector;
    }
}
