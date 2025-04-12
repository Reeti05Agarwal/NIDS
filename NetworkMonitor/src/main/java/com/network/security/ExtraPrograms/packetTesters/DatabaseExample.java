package com.network.security.ExtraPrograms.packetTesters;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class DatabaseExample {
    // Database credentials
    private static final String URL = "jdbc:mysql://localhost:3306/nids"; // Change DB name if needed
    private static final String USER = "root"; // Change username if different
    private static final String PASSWORD = "Maria@mysql05"; // Change to your MySQL password

    public static void main(String[] args) {
        String sql = "INSERT INTO PROTOCOLS (PROTOCOL_ID, PROTOCOL_NAME, DESCRIPTION) VALUES (?, ?, ?)";

        // Using try-with-resources to automatically close resources
        try (Connection conn = DriverManager.getConnection(URL, USER, PASSWORD);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            System.out.println("Connected to MySQL database!");

            // Set values
            pstmt.setInt(1, 8); // Protocol ID
            pstmt.setString(2, "SMTP"); // Fixed typo in protocol name
            pstmt.setString(3, "Simple Mail Transfer Protocol"); // Description

            // Execute insert
            int rowsInserted = pstmt.executeUpdate();
            if (rowsInserted > 0) {
                System.out.println("Data inserted successfully!");
            }

        } catch (SQLException e) {
            System.err.println("Database connection error!");
            e.printStackTrace();
        }
    }
}
