package com.network.security.Intrusion_detection;

public class ProtocolViolationDetection {
    private String protocolName;
    private int expectedPort;
    private int actualPort;

    public ProtocolViolationDetection(String protocolName, int expectedPort, int actualPort) {
        this.protocolName = protocolName;
        this.expectedPort = expectedPort;
        this.actualPort = actualPort;
    }

    // Getters and Setters
    public String getProtocolName() {
        return protocolName;
    }

    public void setProtocolName(String protocolName) {
        this.protocolName = protocolName;
    }

    public int getExpectedPort() {
        return expectedPort;
    }

    public void setExpectedPort(int expectedPort) {
        this.expectedPort = expectedPort;
    }

    public int getActualPort() {
        return actualPort;
    }

    public void setActualPort(int actualPort) {
        this.actualPort = actualPort;
    }

    // Detection logic
    public boolean detect() {
        if (expectedPort != actualPort) {
            System.out.println("⚠️ Protocol violation detected for " + protocolName +
                    ": Expected port " + expectedPort + ", but found " + actualPort);
            return true;
        }
        return false;
    }
}
