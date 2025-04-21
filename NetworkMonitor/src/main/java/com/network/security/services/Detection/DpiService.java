package com.network.security.services.Detection;

import com.network.security.Dao.PacketRetrieverDao;
import com.network.security.Dao.Detection.DpiDetectorDao;
import com.network.security.Intrusion_detection.DpiDetector;
import com.network.security.util.MYSQLconnection;

import java.sql.Connection;
import java.util.Map;

public class DpiService {
    private DpiDetectorDao dpiDetectorDao;
    private DpiDetector dpiDetector;
    PacketRetrieverDao packetRetrieverDao; 

    MYSQLconnection mysqlConnection;
    Connection conn = MYSQLconnection.getConnection();

    // Add a new DPI detection keyword
    public void loadDpiDetectorKeywords(Map<String, Object> packetInfo) {
         try {
            String payload = (String) packetInfo.get("TCP_PAYLOAD");

            if (payload == null) return;

            dpiDetectorDao.loadDpiDetector(conn);
            boolean detected = dpiDetector.detect(payload);  

            if (detected) {
                System.out.println("Deep Packet Inspection detected malicious Strings: " + payload);
            }


        } catch (Exception e) {
            System.err.println("[ERROR] Failed to add DPI detection keyword");
            e.printStackTrace();
        }
    }
}