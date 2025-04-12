package com.network.security.ExtraPrograms.DetectionTest;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class Detection {

    // Maintain history for port scan detection (source IP to destination ports)
    private static final Map<String, Set<Integer>> portScanMap = new ConcurrentHashMap<>();

    // Thresholds
    private static final int PORT_SCAN_THRESHOLD = 10; // Dest port count to trigger warning
    private static final int MAX_PAYLOAD_SIZE = 1500;  // MTU typically ~1500

    public static boolean isMaliciousPacket(Map<String, Object> data) {
        String srcIP = (String) data.get("SRC_IP");
        String destIP = (String) data.get("DEST_IP");
        String srcMAC = (String) data.get("SRC_MAC");
        Integer destPort = parseInt(data.get("DEST_PORT"));
        Integer payloadSize = parseInt(data.get("PAYLOAD_SIZE"));

        // Rule 1: Suspicious MAC
        // Trigger alert if the source MAC address is not in the whitelist

        // Rule 2: Rare/suspicious destination port
        if (destPort != null && (destPort == 31337 || destPort == 4444 || destPort > 49152)) {
            System.out.println("[ALERT] Suspicious port access from " + srcIP + " to port " + destPort);
            return true;
        }

        // Rule 3: Port scanning behavior
        if (srcIP != null && destPort != null) {
            portScanMap.putIfAbsent(srcIP, new HashSet<>());
            portScanMap.get(srcIP).add(destPort);
            if (portScanMap.get(srcIP).size() >= PORT_SCAN_THRESHOLD) {
                System.out.println("[ALERT] Potential port scan detected from " + srcIP);
                return true;
            }
        }

        // Rule 4: Abnormally large payload
        if (payloadSize != null && payloadSize > MAX_PAYLOAD_SIZE) {
            System.out.println("[ALERT] Large payload anomaly from " + srcIP);
            return true;
        }

        // Rule 5: ICMP Abuse (optional)
        String protocol = (String) data.get("PROTOCOL");
        String icmpType = (String) data.get("ICMP_TYPE");
        if ("ICMP".equalsIgnoreCase(protocol) && icmpType != null && !icmpType.matches("0|8|3")) {
            System.out.println("[ALERT] Unusual ICMP Type from " + srcIP + ": " + icmpType);
            return true;
        }

        return false;
    }

    private static Integer parseInt(Object obj) {
        try {
            return obj != null ? Integer.parseInt(obj.toString()) : null;
        } catch (NumberFormatException e) {
            return null;
        }
    }
}

