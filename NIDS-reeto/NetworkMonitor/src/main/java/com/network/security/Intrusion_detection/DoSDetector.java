package com.network.security.Intrusion_detection;

public class DoSDetector {
    private int dosPacketThreshold;
    private int dosTimeWindow;
    private String dosAttackType;

    public DoSDetector(int dosPacketThreshold, int dosTimeWindow) {
        this.dosPacketThreshold = dosPacketThreshold;
        this.dosTimeWindow = dosTimeWindow;
    }

    public boolean detect(int packetCount, int secondsElapsed) {
        if (packetCount > dosPacketThreshold && secondsElapsed <= dosTimeWindow) {
            System.out.println("DDoS attack detected.");
            return true;
        }
        return false;
    }

    public int getDosPacketThreshold() {
        return dosPacketThreshold;
    }

    public void setDosPacketThreshold(int dosPacketThreshold) {
        this.dosPacketThreshold = dosPacketThreshold;
    }

    public int getDosTimeWindow() {
        return dosTimeWindow;
    }

    public void setDosTimeWindow(int dosTimeWindow) {
        this.dosTimeWindow = dosTimeWindow;
    }

    public String getDosAttackType() {
        return dosAttackType;
    }
    public void setDosAttackType(String dosAttackType) {
        this.dosAttackType = dosAttackType;
    }
}
