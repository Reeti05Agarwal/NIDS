package com.network.security.services.Detection;

import com.network.security.Dao.Detection.DpiDetectorDao;
import com.network.security.Intrusion_detection.DpiDetector;
import java.sql.Connection;

public class DpiService {
    private DpiDetectorDao dpiDetectorDao;
    private DpiDetector dpiDetector;

    public DpiService() {
        this.dpiDetector = new DpiDetector("");
        this.dpiDetectorDao = new DpiDetectorDao(dpiDetector);
    }

    // Add a new DPI detection keyword
    public void addDpiDetectorKeyword(Connection conn, String keyword) {
        dpiDetector.setKeyword(keyword);
        dpiDetectorDao.insertDpiDetector(conn);
    }

    // Load the DPI detection keywords from the database and set them in the detector
    public void loadDpiDetectorKeywords(Connection conn) {
        dpiDetectorDao.loadDpiDetector(conn);
    }

    // Detect DPI violation based on content
    public boolean detectDpiViolation(String content) {
        return dpiDetector.detect(content);
    }

    // Update an existing DPI detection keyword
    public void updateDpiDetectorKeyword(Connection conn, String oldKeyword, String newKeyword) {
        dpiDetectorDao.updateDpiDetectorKeyword(conn, oldKeyword, newKeyword);
    }

    // Delete a DPI detection keyword
    public void deleteDpiDetectorKeyword(Connection conn, String keyword) {
        dpiDetectorDao.deleteDpiDetectorKeyword(conn, keyword);
    }
}