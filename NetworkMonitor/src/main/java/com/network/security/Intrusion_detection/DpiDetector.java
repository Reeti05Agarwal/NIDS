package com.network.security.Intrusion_detection;

public class DpiDetector {
    // Deep Packet Inspection (DPI) Detection
    public static final int DPI_THRESHOLD = 100; // Example threshold for DPI detection
    public static final int DPI_TIMEOUT = 1000; // Example timeout for DPI detection
    public static final int DPI_INTERVAL = 1000; // Example interval for DPI detection
    public static final int DPI_MAX_LENGTH = 100; // Example maximum length for DPI detection
    public static final int DPI_MIN_LENGTH = 5; // Example minimum length for DPI detection

    // SQL Injection Detection
    public static final String SQL_INJECTION_PATTERN = ".*(['\";]+|(--|#)).*"; // Example regex pattern for SQL injection
    public static final int SQL_INJECTION_THRESHOLD = 5; // Example threshold for SQL injection detection
    public static final int SQL_INJECTION_TIMEOUT = 1000; // Example timeout for SQL injection detection
    public static final int SQL_INJECTION_INTERVAL = 1000; // Example interval for SQL injection detection
    public static final int SQL_INJECTION_MAX_LENGTH = 100; // Example maximum length for SQL injection detection
    public static final int SQL_INJECTION_MIN_LENGTH = 5; // Example minimum length for SQL injection detection
    public static final int SQL_INJECTION_MAX_EXECUTIONS = 10; // Example maximum executions for SQL injection detection
    public static final int SQL_INJECTION_MAX_EXECUTION_TIME = 1000; // Example maximum execution time for SQL injection detection
    // Cross-Site Scripting (XSS) Detection
    public static final String XSS_PATTERN = ".*(<script>|javascript:|onerror|onload).*"; // Example regex pattern for XSS
    public static final int XSS_THRESHOLD = 5; // Example threshold for XSS detection
    public static final int XSS_TIMEOUT = 1000; // Example timeout for XSS detection
    public static final int XSS_INTERVAL = 1000; // Example interval for XSS detection
    public static final int XSS_MAX_LENGTH = 100; // Example maximum length for XSS detection
    public static final int XSS_MIN_LENGTH = 5; // Example minimum length for XSS detection
    public static final int XSS_MAX_EXECUTIONS = 10; // Example maximum executions for XSS detection
    public static final int XSS_MAX_EXECUTION_TIME = 1000; // Example maximum execution time for XSS detection
    // Cross-Site Request Forgery (CSRF) Detection
    public static final String CSRF_PATTERN = ".*(Referer|Origin).*"; // Example regex pattern for CSRF
    public static final int CSRF_THRESHOLD = 5; // Example threshold for CSRF detection
    public static final int CSRF_TIMEOUT = 1000; // Example timeout for CSRF detection
    public static final int CSRF_INTERVAL = 1000; // Example interval for CSRF detection
    public static final int CSRF_MAX_LENGTH = 100; // Example maximum length for CSRF detection
    public static final int CSRF_MIN_LENGTH = 5; // Example minimum length for CSRF detection
    public static final int CSRF_MAX_EXECUTIONS = 10; // Example maximum executions for CSRF detection
    public static final int CSRF_MAX_EXECUTION_TIME = 1000; // Example maximum execution time for CSRF detection
    // Directory Traversal Detection
    public static final String DIRECTORY_TRAVERSAL_PATTERN = ".*(\\.{2}/|\\..\\\\).*"; // Example regex pattern for directory traversal
    public static final int DIRECTORY_TRAVERSAL_THRESHOLD = 5; // Example threshold for directory traversal detection
    public static final int DIRECTORY_TRAVERSAL_TIMEOUT = 1000; // Example timeout for directory traversal detection
    public static final int DIRECTORY_TRAVERSAL_INTERVAL = 1000; // Example interval for directory traversal detection
    public static final int DIRECTORY_TRAVERSAL_MAX_LENGTH = 100; // Example maximum length for directory traversal detection
    public static final int DIRECTORY_TRAVERSAL_MIN_LENGTH = 5; // Example minimum length for directory traversal detection
    public static final int DIRECTORY_TRAVERSAL_MAX_EXECUTIONS = 10; // Example maximum executions for directory traversal detection
    public static final int DIRECTORY_TRAVERSAL_MAX_EXECUTION_TIME = 1000; // Example maximum execution time for directory traversal detection
    // Command Injection Detection
    public static final String COMMAND_INJECTION_PATTERN = ".*(\\|&;`'\"\\$\\*\\?\\<\\>).*"; // Example regex pattern for command injection
    public static final int COMMAND_INJECTION_THRESHOLD = 5; // Example threshold for command injection detection
    public static final int COMMAND_INJECTION_TIMEOUT = 1000; // Example timeout for command injection detection
    public static final int COMMAND_INJECTION_INTERVAL = 1000; // Example interval for command injection detection
    public static final int COMMAND_INJECTION_MAX_LENGTH = 100; // Example maximum length for command injection detection
    public static final int COMMAND_INJECTION_MIN_LENGTH = 5; // Example minimum length for command injection detection
    public static final int COMMAND_INJECTION_MAX_EXECUTIONS = 10; // Example maximum executions for command injection detection
    public static final int COMMAND_INJECTION_MAX_EXECUTION_TIME = 1000; // Example maximum execution time for command injection detection
    // Session Hijacking Detection

}
