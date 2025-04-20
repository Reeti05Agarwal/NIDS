package com.network.security.Intrusion_detection;

import java.util.List;
import java.util.Map;

public class ProtocolViolationDetection {
    private final Map<String, Integer> restrictedProtocols;

    public ProtocolViolationDetection(List<Map<String, Object>> restrictedProtocolsData) {
        this.restrictedProtocols = loadRestrictions(restrictedProtocolsData);
    }

    // Load the expected ports for each protocol
    private Map<String, Integer> loadRestrictions(List<Map<String, Object>> data) {
        Map<String, Integer> restrictions = new java.util.HashMap<>();
        for (Map<String, Object> row : data) {
            String protocol = ((String) row.get("protocol_name")).toLowerCase();
            Integer port = (Integer) row.get("port");
            restrictions.put(protocol, port);
        }
        return restrictions;
    }

    // Check violations
    public void detectViolations(List<Map<String, Object>> nonStandardPortsData) {
        for (Map<String, Object> row : nonStandardPortsData) {
            String protocol = ((String) row.get("protocol_name")).toLowerCase();
            Integer expected = (Integer) row.get("expected_port");
            Integer actual = (Integer) row.get("actual_port");

            if (restrictedProtocols.containsKey(protocol)) {
                int allowedPort = restrictedProtocols.get(protocol);
                if (!actual.equals(allowedPort)) {
                    System.out.println("⚠ Protocol violation detected for " + protocol +
                            ": Expected port = " + allowedPort + ", but used = " + actual);
                }
            } else {
                System.out.println("ℹ Protocol " + protocol + " is not in the restricted list, skipping.");
            }
        }
    }
}