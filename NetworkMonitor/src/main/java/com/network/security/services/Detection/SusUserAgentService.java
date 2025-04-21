package com.network.security.services.Detection;

import java.sql.Connection;
import java.util.Map;

import com.network.security.Dao.PacketRetrieverDao;
import com.network.security.Dao.Detection.SuspiciousUserAgentDao;
import com.network.security.Intrusion_detection.SuspiciousUserAgentDetection;
import com.network.security.util.MYSQLconnection;
import com.network.security.util.PacketUtils;

public class SusUserAgentService {
    SuspiciousUserAgentDetection susUserAgentDetection;
    SuspiciousUserAgentDao susUserAgentDao;

    MYSQLconnection mysqlConnection;
    Connection conn = MYSQLconnection.getConnection();

    public void loadSuspiciousUserAgent() {
        long latestPacketID = PacketRetrieverDao.getLatestPacketID(); // Loading latest packet ID
        Map<String, Object> packetInfo = PacketRetrieverDao.getPacketData(latestPacketID); // Loading packet data
        Object srcPort = packetInfo.get("SRC_PORT"); 
        Object dstPort = packetInfo.get("DST_PORT");

        if (PacketUtils.parseGetService((int) srcPort, (int) dstPort) == "HTTP"){
            String userAgent = (String) packetInfo.get("USER_AGENT"); // Get User-Agent from packet data
            if (userAgent == null) return; // If no User-Agent, skip this packet

            susUserAgentDao.loadSuspiciousUserAgent(conn); // Load suspicious User-Agent from DB

            if (susUserAgentDetection == null) {
                susUserAgentDetection = new SuspiciousUserAgentDetection();
            }        
            boolean detected = susUserAgentDetection.detect(userAgent); // Check if User-Agent is suspicious

            if (detected) {
                System.out.println("[HTTP] Suspicious User-Agent detected: " + userAgent);
            }
        }

        susUserAgentDao.loadSuspiciousUserAgent(conn);

    }
}
