package com.network.security.Intrusion_detection;

import java.util.List;
import java.util.Map;

public class DpiDetector {
    private List<Map<String, Object>> rules;

    public DpiDetector(List<Map<String, Object>> rules) {
        this.rules = rules;
    }

    public boolean detect(String ruleName, int payloadLength) {
        for (Map<String, Object> rule : rules) {
            String name = (String) rule.get("rule_name");
            int threshold = (int) rule.get("payload_length_threshold");

            if (name.equalsIgnoreCase(ruleName) && payloadLength > threshold) {
                System.out.println("DPI violation detected: " + ruleName);
                return true;
            }
        }
        return false;
    }
}
