package com.network.security.Intrusion_detection;

import java.util.List;
import java.util.Map;

public class DNSWebFilterDetector {
    private List<Map<String, Object>> rules;

    public DNSWebFilterDetector(List<Map<String, Object>> rules) {
        this.rules = rules;
    }

    public boolean detect(String pattern, int occurrences, int seconds) {
        for (Map<String, Object> rule : rules) {
            String rulePattern = (String) rule.get("pattern");
            int threshold = (int) rule.get("threshold");
            int timeWindow = (int) rule.get("time_window_seconds");

            if (rulePattern.equalsIgnoreCase(pattern) &&
                occurrences > threshold && seconds <= timeWindow) {
                System.out.println("DNS filtering triggered for pattern: " + pattern);
                return true;
            }
        }
        return false;
    }
}