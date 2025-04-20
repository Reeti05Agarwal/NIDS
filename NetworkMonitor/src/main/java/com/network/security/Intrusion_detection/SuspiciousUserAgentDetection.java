package com.network.security.Intrusion_detection;

public class SuspiciousUserAgentDetection {
    private String SUDKeyword; 
    
    public SuspiciousUserAgentDetection(String SUDKeyword) {
        this.SUDKeyword = SUDKeyword.toLowerCase();
    }

    public boolean detect(String userAgent) {
        if (userAgent != null && userAgent.toLowerCase().contains(SUDKeyword)) {
            System.out.println("Suspicious User-Agent detected: " + userAgent);
            return true;
        }
        return false;
    }
}
