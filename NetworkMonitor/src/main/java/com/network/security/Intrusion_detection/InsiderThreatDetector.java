package com.network.security.Intrusion_detection;

public class InsiderThreatDetector {
    private int insiderPacketThreshold;
    private int insiderTimeWindow;

    public InsiderThreatDetector(int insiderPacketThreshold, int insiderTimeWindow) {
        this.insiderPacketThreshold = insiderPacketThreshold;
        this.insiderTimeWindow = insiderTimeWindow;
    }

    public int getInsiderPacketThreshold() {
        return insiderPacketThreshold;
    }

    public void setInsiderPacketThreshold(int insiderPacketThreshold) {
        this.insiderPacketThreshold = insiderPacketThreshold;
    }

    public int getInsiderTimeWindow() {
        return insiderTimeWindow;
    }

    public void setInsiderTimeWindow(int insiderTimeWindow) {
        this.insiderTimeWindow = insiderTimeWindow;
    }

    public boolean detect(String service, int failedAttemptsCounts, int seconds) {
        if (failedAttemptsCounts > insiderPacketThreshold && seconds <= insiderTimeWindow) {
            System.out.println("Insider threat detected on service: " + service);
            return true;
        }
        return false;
    }
}
