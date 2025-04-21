package com.network.security.Intrusion_detection;

import java.util.List;

public class SuspiciousUserAgentDetection {
    private List<String> sudKeyword;

    public List<String> getSudKeyword() {
        return sudKeyword;
    }

    public void setSudKeyword(List<String> sudKeyword) {
        this.sudKeyword = sudKeyword;
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
