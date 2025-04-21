package com.network.security.Intrusion_detection;

import java.util.List;

public class ExtICMPDetection {
    private List<String> exticmpIPAddress;
    private String severity;

    public List<String> getExticmpIPAddress() {
        return exticmpIPAddress;
    }

    public void setExticmpIPAddress(List<String> exticmpIPAddress) {
        this.exticmpIPAddress = exticmpIPAddress;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public boolean detect(String srcIP, String destIP) {
        for (String ip : exticmpIPAddress) {
            if (srcIP.equalsIgnoreCase(ip) || destIP.equalsIgnoreCase(ip)) {
                System.out.println("ICMP packet detected from external IP: " + exticmpIPAddress);
                return true;
            }
        }
        return false;
    }
}
