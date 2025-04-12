package com.network.security.ExtraPrograms.DetectionTest;

public class AlertManager {
    public static void alert(String type, String message) {
        System.out.println("[ALERT] " + type + ": " + message);
        // Extend this to email/syslog logging
    }
}
