package com.network.security.Intrusion_detection;

import java.util.List;
import java.util.Map;

public class BruteForceDetector {
    private List<Map<String, Object>> rules;

    public BruteForceDetector(List<Map<String, Object>> rules) {
        this.rules = rules;
    }

    public boolean detect(String service, int failedAttempts, int seconds) {
        for (Map<String, Object> rule : rules) {
            String ruleService = (String) rule.get("service");
            int threshold = (int) rule.get("failed_attempt_threshold");
            int timeWindow = (int) rule.get("time_window_sec");

            if (ruleService.equalsIgnoreCase(service) &&
                failedAttempts > threshold && seconds <= timeWindow) {
                System.out.println("Brute force detected on service: " + service);
                return true;
            }
        }
        return false;
    }
}