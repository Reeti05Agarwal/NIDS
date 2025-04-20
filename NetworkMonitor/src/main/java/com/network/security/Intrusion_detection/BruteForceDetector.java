package com.network.security.Intrusion_detection;

public class BruteForceDetector {
    private int BrutePacketThreshold;
    private int BruteTimeWindow;

    public BruteForceDetector(int BrutePacketThreshold, int BruteTimeWindow) {
        this.BrutePacketThreshold = BrutePacketThreshold;
        this.BruteTimeWindow = BruteTimeWindow;
    }

    public boolean detect(int packetCount, int secondsElapsed) {
        if (packetCount > BrutePacketThreshold && secondsElapsed <= BruteTimeWindow) {
            System.out.println("Brute force attack detected.");
            return true;
        }
        return false;
    }
}