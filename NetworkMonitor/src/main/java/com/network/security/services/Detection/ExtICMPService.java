package com.network.security.Service;

import com.network.security.Dao.Detection.ExtICMPDao;
import com.network.security.Intrusion_detection.ExtICMPDetection;

import java.sql.Connection;

public class ExtICMPService {
    private ExtICMPDao extICMPDao;
    private ExtICMPDetection extICMPDetection;

    public ExtICMPService() {
        this.extICMPDao = new ExtICMPDao();
    }

    // Set detector object in both service and DAO
    public void setDetector(ExtICMPDetection detector) {
        this.extICMPDetection = detector;
        extICMPDao.setExtICMPDetection(detector);
    }

    // Insert rule
    public void insertICMPRule(Connection conn) {
        extICMPDao.insertExtICMPDetection(conn);
    }

    // Load from DB
    public void loadICMPRules(Connection conn) {
        extICMPDao.loadBruteForceThresholds(conn);
    }

    // Update rule
    public void updateICMPRule(Connection conn, String newIPAddress, int id) {
        extICMPDao.updateExtICMPDetection(conn, newIPAddress, id);
    }

    // Delete rule
    public void deleteICMPRule(Connection conn, int id) {
        extICMPDao.deleteExtICMPDetection(conn, id);
    }

    // Detect if packet IP matches ICMP block rule
    public boolean detectICMPIntrusion(String packetIP) {
        if (extICMPDetection == null) {
            System.err.println("[ERROR] Detection logic not initialized.");
            return false;
        }
        return extICMPDetection.detect(packetIP);
    }
}