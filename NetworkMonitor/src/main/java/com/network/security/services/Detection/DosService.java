package com.network.security.services.Detection;

import com.network.security.Dao.Detection.DoSDetectorDao;
import com.network.security.Intrusion_detection.DoSDetector; 
import com.network.security.util.MYSQLconnection;
import com.network.security.util.PacketTracker;
import com.network.security.services.AlertService; // Assuming you have an AlertService class for alerting

import java.sql.Connection;
import java.util.List;
import java.util.Map; 

public class DosService {
    private DoSDetectorDao doSDetectorDao;
    private DoSDetector doSDetector;
    AlertService alertService = new AlertService(); // Assuming you have an AlertService class for alerting
    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(DosService.class); 
    Connection conn = MYSQLconnection.getConnection();

    // Load rule from DB and update doSDetector object
    public void loadDosService(Map<String, Object> packetInfo) {
        try { 
            String sourceIP = (String) packetInfo.get("SRC_IP");
            String destIP = (String) packetInfo.get("DST_IP");
            String protocol = (String) packetInfo.get("PROTOCOL");

            PacketTracker packetTracker = new PacketTracker(doSDetector.getDosTimeWindow());
            int packetCount = packetTracker.incrementAndGetPacketCount(sourceIP);
            int timeElapsed = packetTracker.getTimeElapsedSec(sourceIP);

            String attackType = null;

            switch ((String) packetInfo.get("PROTOCOL")) {
                case "TCP":
                    List<String> flags = (List<String>) packetInfo.get("TCP_FLAGS"); // Retrieving flags list

                    if (flags.contains("SYN") && !flags.contains("ACK")) {
                        attackType = "SYN_FLOOD";
                    } else if (flags.contains("ACK") && flags.contains("SYN")) {
                        attackType = "ACK_FLOOD";
                    } else if (flags.contains("FIN") && flags.contains("ACK")) {
                        attackType = "FIN_FLOOD";
                    } else if (flags.contains("RST") && flags.contains("ACK")) {
                        attackType = "RST_FLOOD";
                    } else if (flags.contains("PSH") && flags.contains("ACK")) {
                        attackType = "PSH_FLOOD";
                    } else {
                        attackType = "UNKNOWN_TCP_ATTACK";
                    }
                    break;

                case "UDP":
                    attackType = "UDP_FLOOD";
                    break;

                case "ICMP":
                    attackType = "ICMP";
                    break;

                default:
                    System.out.println("[ERROR] Unknown protocol type: "+ packetInfo.get("PROTOCOL"));
                    return;
            }

            if (attackType != null) {
                doSDetectorDao.loadDoSDetector(conn, attackType);

                if (doSDetector.detect(packetCount, timeElapsed)) {
                    System.out.println("[ALERT] DoS Attack Detected - Type: " + doSDetector.getDosAttackType()
                            + " | Packet Count: " + packetCount
                            + " | Time Elapsed: " + timeElapsed + " sec");
                    LOGGER.info("[ALERT] DoS Attack Detected - Type: " + doSDetector.getDosAttackType()
                            + " | Packet Count: " + packetCount
                            + " | Time Elapsed: " + timeElapsed + " sec");
                            alertService.triggerAlert(
                                conn,
                                sourceIP != null ? sourceIP : "UNKNOWN",
                                destIP != null ? destIP : "UNKNOWN",
                                protocol != null ? protocol : "UNKNOWN",
                                2, // Assume rule_id = 2 for DoS attack rules
                                doSDetector.getSeverity(),
                                "[DoS Attack] Type: " + doSDetector.getDosAttackType() 
                                    + ", Packets: " + packetCount 
                                    + ", Time: " + timeElapsed + " sec"
                            );
                }
            }
        } catch (Exception e) {
            System.err.println("[ERROR] Failed in DoS detection service");
            LOGGER.error("[ERROR] Failed in DoS detection service", e);
            e.printStackTrace();
        }
    }

     

 
}

