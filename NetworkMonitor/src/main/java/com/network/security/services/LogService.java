// src/main/java/com/network/security/services/LogService.java
package com.network.security.services;

import java.util.List;

import com.network.security.Dao.LogDao;
import com.network.security.entity.LogEntry;

public class LogService {

    private final LogDao dao = new LogDao();

    /**
     * Record a login or logout event for the given user.
     */
    public void logEvent(String username, String role, String event) {
        dao.insertLog(username, role, event);
    }

    /**
     * Fetch all log entries, newest first.
     */
    public List<LogEntry> getAllLogs() {
        return dao.getAllLogs();
    }
}
