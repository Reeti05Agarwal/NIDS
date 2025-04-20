package com.network.security.Intrusion_detection;

import java.util.List;

public class ExtICMPDetection {
    private List<String> exticmpIPAddress;

    public ExtICMPDetection(List<String> exticmpIPAddress) {
        this.exticmpIPAddress = exticmpIPAddress;
    }

    public List<String> getExticmpIPAddress() {
        return exticmpIPAddress;
    }

    public void setExticmpIPAddress(List<String> exticmpIPAddress) {
        this.exticmpIPAddress = exticmpIPAddress;
    }

    public boolean detect(String packetIP) {
        for (String ip : exticmpIPAddress) {
            if (packetIP.equalsIgnoreCase(ip)) {
                System.out.println("ICMP packet detected from external IP: " + exticmpIPAddress);
                return true;
            }
        }
        return false;
    }
}
