package com.network.security.Intrusion_detection;

public class DNSWebFilterDetector {
    private String DNSWebFilterPattern;
    private int DNSWebFilterThreshold;
    private int DNSWebFilterTimeWindow;

    public DNSWebFilterDetector(String DNSWebFilterPattern, int DNSWebFilterThreshold, int DNSWebFilterTimeWindow) {
        this.DNSWebFilterPattern = DNSWebFilterPattern;
        this.DNSWebFilterThreshold = DNSWebFilterThreshold;
        this.DNSWebFilterTimeWindow = DNSWebFilterTimeWindow;
    }

    public boolean detect(String dnsQuery, int queryCount, int secondsElapsed) {
        if (dnsQuery.contains(DNSWebFilterPattern) && queryCount > DNSWebFilterThreshold && secondsElapsed <= DNSWebFilterTimeWindow) {
            System.out.println("DNS Web Filter attack detected.");
            return true;
        }
        return false;
    }
}