package com.network.security.Intrusion_detection;

public class DoSDetector {
    private int dosPacketThreshold;
    private int dosTimeWindow;
    private String dosAttackType;
    private String severity;

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

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public boolean detect(int packetCount, int secondsElapsed) {
        return packetCount > dosPacketThreshold && secondsElapsed <= dosTimeWindow; 
        
    }
}
