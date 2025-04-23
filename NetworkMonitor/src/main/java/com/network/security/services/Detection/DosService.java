package com.network.security.services.Detection;

import com.network.security.Dao.Detection.DoSDetectorDao;
import com.network.security.Intrusion_detection.DoSDetector; 
import com.network.security.util.DBConnection;
import com.network.security.util.PacketTracker;
import com.network.security.services.AlertService; // Assuming you have an AlertService class for alerting

import java.sql.Connection; 
import java.util.Map; 

public class DosService {
    private DoSDetectorDao doSDetectorDao;
    private DoSDetector doSDetector;
    AlertService alertService = new AlertService(); // Assuming you have an AlertService class for alerting
    Connection conn = DBConnection.getConnection();

    // Load rule from DB and update doSDetector object
    public void loadDosService(Map<String, Object> packetInfo) {
        try { 
            System.out.println("[DDoS SERVICE] Starting DDoS Attack Detection Function");
            String protocol = null;
            String sourceIP = null;
            String destIP = null;
            String attackType = null;

            if (packetInfo.get("srcIP") != null){
                sourceIP = (String) packetInfo.get("srcIP");
                destIP = (String) packetInfo.get("destIP");
            }
            else{
                System.out.println("[DDoS SERVICE] Source and Destination IP is NULL");
                return;
            }
            
            if (packetInfo.get("PROTOCOL") != null){
                protocol = (String) packetInfo.get("PROTOCOL");
            }
            else{
                System.out.println("[DDoS SERVICE] Protocol is NULL");
                return;
            }
            switch (protocol) {
                case "TCP":
                    String flags = (String) packetInfo.get("FLAGS"); // Retrieving flags list

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
                if (conn == null) {
                    System.out.println("[CONN ERROR] Database connection is null");
                    return;
                }

                PacketTracker packetTracker = new PacketTracker(doSDetector.getDosTimeWindow());
                int packetCount = packetTracker.incrementAndGetPacketCount(sourceIP);
                int timeElapsed = packetTracker.getTimeElapsedSec(sourceIP);
                System.out.println("[DDoS SERVICE] Packet Count: " + packetCount);
                System.out.println("[DDoS SERVICE] Time Elapsed Between the packets: " + timeElapsed);
                if (packetCount==0 || timeElapsed == 0) return;

                doSDetectorDao.loadDoSDetector(conn, attackType);
                System.out.println("[DDoS SERVICE] Thresholds loaded");
                boolean detected = doSDetector.detect(packetCount, timeElapsed); 
                
                if (detected) {
                    System.out.println("[ALERT] DoS Attack Detected - Type: " + doSDetector.getDosAttackType()
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
                else{
                    System.out.println("DoS Attack NOT Detected");
                }
            }
        } catch (Exception e) {
            System.err.println("[ERROR] Failed in DoS detection service");
            e.printStackTrace();
        }
    }

     

 
}

