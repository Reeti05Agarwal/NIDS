package com.network.security.DetectionTest;

import java.util.Map;

public class AnomalyDetector {
     public static void detectAnomaly(Map<String, Object> packetData) {
        String srcIp = (String) packetData.get("SRC_IP");
        String destIp = (String) packetData.get("DEST_IP");
        int protocol = (Integer) packetData.get("PROTOCOL_NAME");
        int totalLength = (Integer) packetData.get("TOTAL_LENGTH");
        int ttl = (Integer) packetData.get("TTL");

        // Rule: Unusually large packet size (potential DoS attack)
        if (totalLength > 1500) {
            System.out.println("[ALERT] Possible DoS Attack detected from " + srcIp);
        }

        // Rule: Abnormal TTL values (Packet Spoofing)
        if (ttl < 10 || ttl > 255) {
            System.out.println("[ALERT] Possible Packet Spoofing detected from " + srcIp);
        }

        // Rule: UDP Flood Attack Detection
        if (protocol == 17 && totalLength > 1000) {
            System.out.println("[ALERT] Possible UDP Flood from " + srcIp);
        }

        // Add more rules based on at tack patterns...
    }
}
