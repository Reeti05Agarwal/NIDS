package com.network.security.Intrusion_detection;

public class InsiderThreatDetector {
    private int insiderPacketThreshold;
    private int insiderTimeWindow;
    private String severity;
 

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

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public boolean detect(String service, int failedAttemptsCounts, int seconds) {
        if (failedAttemptsCounts > insiderPacketThreshold && seconds <= insiderTimeWindow) {
            System.out.println("Insider threat detected on service: " + service);
            return true;
        }
        return false;
    }
}
