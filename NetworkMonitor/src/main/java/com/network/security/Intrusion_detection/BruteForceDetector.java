package com.network.security.Intrusion_detection;

/*
 * Holds threshold/time window and runs detection logic
 */

public class BruteForceDetector {
    private int brutePacketThreshold;
    private int bruteTimeWindow;

    // public BruteForceDetector(int brutePacketThreshold, int bruteTimeWindow) {
    //     this.brutePacketThreshold = brutePacketThreshold;
    //     this.bruteTimeWindow = bruteTimeWindow;
    // }

    // Getters and Setters
    public int getBrutePacketThreshold() {
        return brutePacketThreshold;
    }
    public void setBrutePacketThreshold(int brutePacketThreshold) {
        this.brutePacketThreshold = brutePacketThreshold;
    }
    public int getBruteTimeWindow() {
        return bruteTimeWindow;
    }
    public void setBruteTimeWindow(int bruteTimeWindow) {
        this.bruteTimeWindow = bruteTimeWindow;
    }

    // Method to detect brute force attacks based on packet count and time window
    public boolean detect(int packetCount, int secondsElapsed) {
        if (packetCount > brutePacketThreshold && secondsElapsed <= bruteTimeWindow) {
            System.out.println("Brute force attack detected.");
            return true;
        }
        return false;
    }
}
