package com.network.security.services.Detection;

import com.network.security.Dao.PacketRetrieverDao;
import com.network.security.Dao.Detection.DpiDetectorDao;
import com.network.security.Intrusion_detection.DpiDetector;
import com.network.security.util.MYSQLconnection;
import com.network.security.Service.AlertService;

import java.sql.Connection;
import java.util.Map;

public class DpiService {
    private DpiDetectorDao dpiDetectorDao = new DpiDetectorDao();
    private DpiDetector dpiDetector = new DpiDetector();
    private PacketRetrieverDao packetRetrieverDao; 

    private AlertService alertService = new AlertService();

    MYSQLconnection mysqlConnection;
    Connection conn = MYSQLconnection.getConnection();

    // DPI detection based on malicious payloads
    public void loadDpiDetectorKeywords(Map<String, Object> packetInfo) {
        try {
            String payload = (String) packetInfo.get("TCP_PAYLOAD");
            String srcIP = (String) packetInfo.get("SRC_IP");
            String destIP = (String) packetInfo.get("DST_IP");
            String protocol = (String) packetInfo.get("PROTOCOL");

            if (payload == null) return;

            dpiDetectorDao.loadDpiDetector(conn);
            boolean detected = dpiDetector.detect(payload);  

            if (detected) {
                System.out.println("[ALERT] Deep Packet Inspection detected malicious content in payload: " + payload);

                alertService.triggerAlert(
                    conn,
                    srcIP != null ? srcIP : "UNKNOWN",
                    destIP != null ? destIP : "UNKNOWN",
                    protocol != null ? protocol : "UNKNOWN",
                    3, // Assume rule_id = 3 for DPI detection
                    dpiDetector.getSeverity(),
                    "[DPI Detection] Malicious payload string matched: " + payload
                );
            }

        } catch (Exception e) {
            System.err.println("[ERROR] Failed in DPI detection service");
            e.printStackTrace();
        }
    }
}
