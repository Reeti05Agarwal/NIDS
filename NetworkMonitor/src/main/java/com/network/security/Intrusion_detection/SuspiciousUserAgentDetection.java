package com.network.security.Intrusion_detection;

public class SuspiciousUserAgentDetection {
    private String sudKeyword;

    public SuspiciousUserAgentDetection(String sudKeyword) {
        this.sudKeyword = sudKeyword.toLowerCase();
    }

    public String getSudKeyword() {
        return sudKeyword;
    }

    public void setSudKeyword(String sudKeyword) {
        this.sudKeyword = sudKeyword.toLowerCase();
    }

    public boolean detect(String userAgent) {
        if (userAgent != null && userAgent.toLowerCase().contains(sudKeyword)) {
            System.out.println("Suspicious User-Agent detected: " + userAgent);
            return true;
        }
        return false;
    }
}
