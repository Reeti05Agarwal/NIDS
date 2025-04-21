package com.network.security.Intrusion_detection;

import java.util.List;

public class SuspiciousUserAgentDetection {
    private List<String> sudKeyword;
    private String severity;

    public List<String> getSudKeyword() {
        return sudKeyword;
    }

    public void setSudKeyword(List<String> sudKeyword) {
        this.sudKeyword = sudKeyword;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public boolean detect(String userAgent) {
        for (String keyword : sudKeyword) {
            if (userAgent != null && userAgent.toLowerCase().contains(keyword.toLowerCase())) {
                System.out.println("Suspicious User-Agent detected: " + userAgent);
                return true;
            }
        }
        return false;
    }
}
