package com.network.security.services.Detection;

import com.network.security.Dao.PacketRetrieverDao;
import com.network.security.Dao.Detection.ExtICMPDao;
import com.network.security.Intrusion_detection.ExtICMPDetection;
import com.network.security.util.MYSQLconnection;
import com.network.security.Service.AlertService;

import java.sql.Connection;
import java.util.Map;

public class ExtICMPService {
    private ExtICMPDao extICMPDao = new ExtICMPDao();
    private ExtICMPDetection extICMPDetection = new ExtICMPDetection();
    PacketRetrieverDao packetRetrieverDao;

    AlertService alertService = new AlertService();

    MYSQLconnection mysqlConnection;
    Connection conn = MYSQLconnection.getConnection();

    // Load External ICMP rules and perform detection
    public void loadICMPRules(Map<String, Object> packetInfo) {
        try {
            String srcIP = (String) packetInfo.get("SRC_IP");
            String dstIP = (String) packetInfo.get("DST_IP");
            String protocol = (String) packetInfo.getOrDefault("PROTOCOL", "ICMP");

            extICMPDao.loadICMPip(conn);

            boolean detected = extICMPDetection.detect(srcIP, dstIP);

            if (detected) {
                System.out.println("[ALERT] External ICMP Blacklist attack detected from IP: " + srcIP + " to " + dstIP);

                alertService.triggerAlert(
                    conn,
                    srcIP != null ? srcIP : "UNKNOWN",
                    dstIP != null ? dstIP : "UNKNOWN",
                    protocol,
                    4, // Assume rule_id = 4 for External ICMP detection
                    extICMPDetection.getSeverity(),
                    "[External ICMP Detection] Blacklisted IP triggered alert"
                );
            }

        } catch (Exception e) {
            System.err.println("[ERROR] Failed to load ICMP detection data");
            e.printStackTrace();
        }
    }
}
