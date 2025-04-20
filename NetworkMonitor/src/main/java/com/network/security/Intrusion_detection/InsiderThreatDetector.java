package com.network.security.Intrusion_detection;

public class InsiderThreatDetector {
    private int InsiderePacketThreshold;
    private int InsiderTimeWindow;

    public InsiderThreatDetector(int InsiderePacketThreshold, int InsiderTimeWindow) {
        this.InsiderePacketThreshold = InsiderePacketThreshold;
        this.InsiderTimeWindow = InsiderTimeWindow;
    }

    public boolean detect(String service, int failedAttemptsCounts, int seconds) {
        if (service.equalsIgnoreCase(service) &&
            failedAttemptsCounts > InsiderePacketThreshold && seconds <= InsiderTimeWindow) {
            System.out.println("Insider threat detected on service: " + service);
            return true;
        }        
        return false;
    }
}