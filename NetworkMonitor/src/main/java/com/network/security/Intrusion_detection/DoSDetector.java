package com.network.security.Intrusion_detection;

import java.util.Map;

public class DoSDetector {
    private int packetThreshold;
    private int timeWindow;

    public DoSDetector(Map<String, Object> ddosRule) {
        this.packetThreshold = (int) ddosRule.get("packet_threshold");
        this.timeWindow = (int) ddosRule.get("time_window_sec");
    }

    public boolean detect(int packetCount, int secondsElapsed) {
        if (packetCount > packetThreshold && secondsElapsed <= timeWindow) {
            System.out.println("DDoS attack detected.");
            return true;
        }
        return false;
    }
}