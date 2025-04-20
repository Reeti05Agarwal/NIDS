package com.network.security.Intrusion_detection;

public class ExtICMPDetection {
    String ExticmpIPAddress;

    public ExtICMPDetection(String ExticmpIPAddress) {
        this.ExticmpIPAddress = ExticmpIPAddress;
    }

    public boolean detect(String packetIP) {
        if (packetIP.equalsIgnoreCase(ExticmpIPAddress)) {
            System.out.println("ICMP packet detected from external IP: " + ExticmpIPAddress);
            return true;
        }
        return false;
    }
}
