package com.network.security.services.Detection;

import java.sql.Connection;
 
import com.network.security.Dao.Detection.InsiderThreatDao;
import com.network.security.util.MYSQLconnection;
import com.network.security.Intrusion_detection.InsiderThreatDetector;

public class InsiderThreatService {
    private InsiderThreatDao insiderThreatDao;
    private InsiderThreatDetector insiderThreatDetector; 
    Connection conn = MYSQLconnection.getConnection();

    public void loadInsiderThreat() {
        try {
            


            insiderThreatDao.loadInsiderThreatDetector(conn);
             
        } catch (Exception e) {
            System.err.println("[ERROR] Failed to load insider threat detection data");
            e.printStackTrace();
        }
    }

    // Optional method to perform detection
    public void checkInsiderThreat(String service, int failedAttempts, int timeInSeconds) {
        if (insiderThreatDetector.detect(service, failedAttempts, timeInSeconds)) {
            System.out.println("[ALERT] Insider threat severity: " + insiderThreatDetector.getSeverity());
            // You can add logging or database entry here
        } else {
            System.out.println("[INFO] No insider threat detected.");
        }
    }
}
