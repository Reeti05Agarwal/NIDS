package com.network.security.services.Detection;

import java.sql.Connection;
import java.util.Map;

import com.network.security.Dao.Detection.SuspiciousUserAgentDao;
import com.network.security.Intrusion_detection.SuspiciousUserAgentDetection;
import com.network.security.util.DBConnection;
import com.network.security.util.PacketUtils;

public class SusUserAgentService {

    SuspiciousUserAgentDetection susUserAgentDetection;
    SuspiciousUserAgentDao susUserAgentDao;

    DBConnection mysqlConnection;
    Connection conn = DBConnection.getConnection();

    public void loadSuspiciousUserAgent(Map<String, Object> packetInfo) {
        Object srcPort = packetInfo.get("SRC_PORT");
        Object dstPort = packetInfo.get("DST_PORT");

        // Check if the packet is HTTP
        if (PacketUtils.parseGetService((int) srcPort, (int) dstPort) == "HTTP") {
            String userAgent = (String) packetInfo.get("USER_AGENT");
            if (userAgent == null) {
                return;
            }

            susUserAgentDao.loadSuspiciousUserAgent(conn);

            if (susUserAgentDetection == null) {
                susUserAgentDetection = new SuspiciousUserAgentDetection();
            }
            boolean detected = susUserAgentDetection.detect(userAgent);

            if (detected) {
                System.out.println("[HTTP] Suspicious User-Agent detected: " + userAgent);
            }
        }
        return;
    }
}
