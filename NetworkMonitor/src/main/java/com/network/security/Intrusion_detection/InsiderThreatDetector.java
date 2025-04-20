package com.network.security.Intrusion_detection;

import java.util.List;
import java.util.Map;

public class InsiderThreatDetector {
    private List<Map<String, Object>> rules;

    public InsiderThreatDetector(List<Map<String, Object>> rules) {
        this.rules = rules;
    }

    public boolean detect(String ruleType, int accessCount, int timeElapsed) {
        for (Map<String, Object> rule : rules) {
            String rType = (String) rule.get("rule_type");
            int threshold = (int) rule.get("access_threshold");
            int timeWindow = (int) rule.get("time_window_sec");

            if (rType.equalsIgnoreCase(ruleType) &&
                accessCount > threshold && timeElapsed <= timeWindow) {
                System.out.println("Insider threat detected: " + rule.get("rule_name"));
                return true;
            }
        }
        return false;
    }
}