package com.network.security.Service;

import com.network.security.Dao.Alert.AlertDao;

import java.sql.Connection;

public class AlertService {

    private AlertDao alertDao;

    public AlertService() {
        this.alertDao = new AlertDao();
    }

    // Service method to trigger an alert
    public void triggerAlert(Connection conn, String sourceIp, String destinationIp, String protocol,
                             int ruleId, String severity, String alertMessage) {
        alertDao.insertAlert(conn, sourceIp, destinationIp, protocol, ruleId, severity, alertMessage);
    }

    // Service method to display all alerts
    public void showAllAlerts(Connection conn) {
        alertDao.getAllAlerts(conn);
    }
}
