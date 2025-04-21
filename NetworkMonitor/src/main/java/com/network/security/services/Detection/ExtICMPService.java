package com.network.security.services.Detection;

import java.sql.Connection;
import java.util.Map;

import com.network.security.Dao.Detection.ExtICMPDao;
import com.network.security.Dao.PacketRetrieverDao;
import com.network.security.Intrusion_detection.ExtICMPDetection;
import com.network.security.util.DBConnection;

public class ExtICMPService {

    private ExtICMPDao extICMPDao;
    private ExtICMPDetection extICMPDetection;
    PacketRetrieverDao packetRetrieverDao;

    DBConnection mysqlConnection;
    Connection conn = DBConnection.getConnection();

    // Load from DB
    public void loadICMPRules(Map<String, Object> packetInfo) {
        try {
            String srcIP = (String) packetInfo.get("SRC_IP");
            String dstIP = (String) packetInfo.get("DST_IP");

            extICMPDao.loadICMPip(conn);

            if (extICMPDetection == null) {
                extICMPDetection = new ExtICMPDetection();
            }
            boolean detected = extICMPDetection.detect(srcIP, dstIP);

            if (detected) {
                System.out.println("External ICMP Black attack detected from IP: " + srcIP + " to " + dstIP);
            }

        } catch (Exception e) {
            System.err.println("[ERROR] Failed to load ICMP detection data");
            e.printStackTrace();
        }
    }

}
