// src/main/java/com/network/security/services/AlertService.java
package com.network.security.services;

import java.sql.Connection;

import com.network.security.Dao.AlertDao;
import com.network.security.util.DBConnection;

/**
 * Service layer for alert operations, used by the UI.
 */
public class AlertService {

    private final AlertDao alertDao = new AlertDao();

    /**
     * Triggers a new alert by inserting into the database.
     */
    public void triggerAlert(String sourceIp,
            String destinationIp,
            String protocol,
            int ruleId,
            String severity,
            String alertMessage) {
        try (Connection conn = DBConnection.getConnection()) {
            alertDao.insertAlert(conn, sourceIp, destinationIp, protocol, ruleId, severity, alertMessage);
        } catch (Exception e) {
            throw new RuntimeException("Failed to trigger alert", e);
        }
    }

    /**
     * Fetches and prints all alerts (legacy).
     */
    public void showAllAlerts() {
        try (Connection conn = DBConnection.getConnection()) {
            alertDao.getAllAlerts(conn);
        } catch (Exception e) {
            throw new RuntimeException("Failed to fetch alerts", e);
        }
    }
}
