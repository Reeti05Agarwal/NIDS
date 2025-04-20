package com.network.security.Intrusion_detection;

public class DNSWebFilterDetector {
    private String dnsWebFilterPattern;
    private int dnsWebFilterThreshold;
    private int dnsWebFilterTimeWindow;

    public DNSWebFilterDetector(String dnsWebFilterPattern, int dnsWebFilterThreshold, int dnsWebFilterTimeWindow) {
        this.dnsWebFilterPattern = dnsWebFilterPattern;
        this.dnsWebFilterThreshold = dnsWebFilterThreshold;
        this.dnsWebFilterTimeWindow = dnsWebFilterTimeWindow;
    }

    public String getDnsWebFilterPattern() {
        return dnsWebFilterPattern;
    }

    public void setDnsWebFilterPattern(String dnsWebFilterPattern) {
        this.dnsWebFilterPattern = dnsWebFilterPattern;
    }

    public int getDnsWebFilterThreshold() {
        return dnsWebFilterThreshold;
    }

    public void setDnsWebFilterThreshold(int dnsWebFilterThreshold) {
        this.dnsWebFilterThreshold = dnsWebFilterThreshold;
    }

    public int getDnsWebFilterTimeWindow() {
        return dnsWebFilterTimeWindow;
    }

    public void setDnsWebFilterTimeWindow(int dnsWebFilterTimeWindow) {
        this.dnsWebFilterTimeWindow = dnsWebFilterTimeWindow;
    }

    public boolean detect(String dnsQuery, int queryCount, int secondsElapsed) {
        if (dnsQuery.contains(dnsWebFilterPattern) && queryCount > dnsWebFilterThreshold && secondsElapsed <= dnsWebFilterTimeWindow) {
            System.out.println("DNS Web Filter attack detected.");
            return true;
        }
        return false;
    }
}
