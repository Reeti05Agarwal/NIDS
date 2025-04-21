// src/main/java/com/network/security/entity/Alert.java
package com.network.security.entity;

import java.sql.Timestamp;

public class Alert {

    private final Timestamp timestamp;
    private final String sourceIp;
    private final String destinationIp;
    private final String protocol;
    private final String severity;
    private final String alertMessage;

    public Alert(Timestamp timestamp,
            String sourceIp,
            String destinationIp,
            String protocol,
            String severity,
            String alertMessage) {
        this.timestamp = timestamp;
        this.sourceIp = sourceIp;
        this.destinationIp = destinationIp;
        this.protocol = protocol;
        this.severity = severity;
        this.alertMessage = alertMessage;
    }

    // getters...
    public Timestamp getTimestamp() {
        return timestamp;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public String getDestinationIp() {
        return destinationIp;
    }

    public String getProtocol() {
        return protocol;
    }

    public String getSeverity() {
        return severity;
    }

    public String getAlertMessage() {
        return alertMessage;
    }
}
