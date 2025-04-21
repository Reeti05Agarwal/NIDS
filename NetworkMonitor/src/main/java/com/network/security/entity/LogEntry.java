// src/main/java/com/network/security/entity/LogEntry.java
package com.network.security.entity;

import java.sql.Timestamp;

public class LogEntry {

    private int id;
    private String username;
    private String role;
    private String event;
    private Timestamp eventTime;

    public LogEntry(int id, String username, String role, String event, Timestamp eventTime) {
        this.id = id;
        this.username = username;
        this.role = role;
        this.event = event;
        this.eventTime = eventTime;
    }

    // getters
    public int getId() {
        return id;
    }

    public String getUsername() {
        return username;
    }

    public String getRole() {
        return role;
    }

    public String getEvent() {
        return event;
    }

    public Timestamp getEventTime() {
        return eventTime;
    }
}
