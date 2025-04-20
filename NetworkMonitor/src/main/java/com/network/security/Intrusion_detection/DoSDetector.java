package com.network.security.Intrusion_detection;

public class DoSDetector {
    private int DoSPacketThreshold;
    private int DoSTimeWindow;

    public DoSDetector(int DoSPacketThreshold, int DoSTimeWindow) {
        this.DoSPacketThreshold = DoSPacketThreshold;
        this.DoSTimeWindow = DoSTimeWindow;
    }

    public boolean detect(int packetCount, int secondsElapsed) {
        if (packetCount > DoSPacketThreshold && secondsElapsed <= DoSTimeWindow) {
            System.out.println("DDoS attack detected.");
            return true;
        }
        return false;
    }

    // getters and setters for packetThreshold and timeWindow
}