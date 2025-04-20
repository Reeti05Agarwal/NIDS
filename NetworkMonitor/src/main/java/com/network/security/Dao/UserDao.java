package com.network.security.Dao;

import com.network.security.entity.User;
import com.network.security.entity.Role;
import com.network.security.util.MYSQLconnection;
import java.sql.*;
import java.util.Map;

/*
 * FUNCTIONS:
 * 1. Add User
 * 2. Update User
 * 3. Delete User
 * 4. Change Role
 */

public class UserDao {

    String DB_URL = System.getenv("DB_URL");
    String DB_USER = System.getenv("DB_USER");
    String DB_PASSWORD = System.getenv("DB_PASSWORD");

    MYSQLconnection mysqlConnection = new MYSQLconnection();
    
    private final Connection connection;

    public UserDao(Connection connection) {
        this.connection = connection;
    }

    public void createUser(User user) throws SQLException {
        String sql = "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, user.getUsername());
            stmt.setString(2, user.getPasswordHash());
            stmt.setString(3, user.getRole().name());
            stmt.executeUpdate();
        }
    }

    public User getUserByUsername(String username) throws SQLException {
        String sql = "SELECT * FROM users WHERE username = ?";
        try (PreparedStatement stmt = connection.prepareStatement(sql)) {
            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return new User(
                    rs.getInt("id"),
                    rs.getString("username"),
                    rs.getString("password_hash"),
                    Role.valueOf(rs.getString("role"))
                );
            }
        }
        return null;
    }


    static void AddingUser(Map<String, Object> UserData) {
        if (UserData.isEmpty()) {
            System.err.println("[ERROR] Skipping invalid packet...");
            return;
        }
    
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            String insertQuery = "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)"; 
            PreparedStatement stmt = conn.prepareStatement(insertQuery);
            stmt.setString(1, (String) UserData.get("Username"));
            stmt.setString(2, (String) UserData.get("Password"));
            stmt.setString(3, (String) UserData.get("Role"));
            stmt.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    static void UpdateUser(Map<String, Object> UserData) {
        if (UserData.isEmpty()) {
            System.err.println("[ERROR] Skipping invalid packet...");
            return;
        }
    
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            String updateQuery = "UPDATE users SET password_hash = ?, role = ? WHERE username = ?"; 
            PreparedStatement stmt = conn.prepareStatement(updateQuery);
            stmt.setString(1, (String) UserData.get("Password"));
            stmt.setString(2, (String) UserData.get("Role"));
            stmt.setString(3, (String) UserData.get("Username"));
            stmt.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
 

    static void DeleteUser(Map<String, Object> UserData) {
        if (UserData.isEmpty()) {
            System.err.println("[ERROR] Skipping invalid packet...");
            return;
        }
    
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            String deleteQuery = "DELETE FROM users WHERE username = ?";
            PreparedStatement stmt = conn.prepareStatement(deleteQuery);
            stmt.setString(1, (String) UserData.get("Username"));
            stmt.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    static void ChangeRole(Map<String, Object> UserData) {
        if (UserData.isEmpty()) {
            System.err.println("[ERROR] Skipping invalid packet...");
            return;
        }
    
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            String updateRoleQuery = "UPDATE users SET role = ? WHERE username = ?";
            PreparedStatement stmt = conn.prepareStatement(updateRoleQuery);
            stmt.setString(1, (String) UserData.get("Role"));
            stmt.setString(2, (String) UserData.get("Username"));
            stmt.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}
