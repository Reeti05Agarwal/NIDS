package com.network.security.services;

import java.sql.Connection;
import com.network.security.util.MYSQLconnection;
import com.network.security.Dao.Detection.BruteForceDao;
import com.network.security.Intrusion_detection.BruteForceDetector;

public class RuleServices {
    private BruteForceDetector bruteForceDetector;
    private BruteForceDao bruteForceDao;

    // class
    public RuleServices() {
        // Use the utility class to get DB connection
        Connection conn = MYSQLconnection.getConnection();

        // Proceed only if connection is successful
        if (conn != null) {

            // 
            bruteForceDetector = new BruteForceDetector(0, 0);
            bruteForceDao = new BruteForceDao(bruteForceDetector);
            bruteForceDao.loadBruteForceThresholds(conn);

            


        } else {
            System.err.println("[ERROR] Could not initialize DetectionServices due to DB error.");
        }
    }
 
}
