package com.network.security.Intrusion_detection;

public class ExtICMPDetection {
    private String exticmpIPAddress;

    public ExtICMPDetection(String exticmpIPAddress) {
        this.exticmpIPAddress = exticmpIPAddress;
    }

    public String getExticmpIPAddress() {
        return exticmpIPAddress;
    }

    public void setExticmpIPAddress(String exticmpIPAddress) {
        this.exticmpIPAddress = exticmpIPAddress;
    }

    public boolean detect(String packetIP) {
        if (packetIP.equalsIgnoreCase(exticmpIPAddress)) {
            System.out.println("ICMP packet detected from external IP: " + exticmpIPAddress);
            return true;
        }
        return false;
    }
}
