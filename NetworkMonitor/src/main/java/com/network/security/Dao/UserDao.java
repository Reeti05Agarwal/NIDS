package com.network.security.dao;

import com.network.security.entity.User;
import com.network.security.entity.Role;

import java.sql.*;
import java.util.Map;

public class UserDao {
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
            // Super Table: Packet Metadata
            String insertQuery_NewUser = "INSERT INTO User (Username, Password, Role) VALUES (?, ?, ?)"; 
            PreparedStatement stmt_NewUser = conn.prepareStatement(insertQuery_NewUser);
            stmt_NewUser.setString(1, (String) UserData.get("Username"));
            stmt_NewUser.setString(2, (String) UserData.get("Password"));
            stmt_NewUser.setString(3, (String) UserData.get("Role"));
             
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    static void UpdateUser(Map<String, Object> UserData) {
        if (UserData.isEmpty()) {
            System.err.println("[ERROR] Skipping invalid packet...");
            return;
        }

        // PROPERLY WRITE THE CODE
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            // Super Table: Packet Metadata
            String insertQuery_UpdateUser = "UPDATE INTO User (Username, Password, Role) VALUES (?, ?, ?)"; 
            PreparedStatement stmt_UpdateUser = conn.prepareStatement(insertQuery_UpdateUser);
            stmt_UpdateUser.setString(1, (String) UserData.get("Username"));
            stmt_UpdateUser.setString(2, (String) UserData.get("Password"));
            stmt_UpdateUser.setString(3, (String) UserData.get("Role"));
             
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    static void DeleteUser(Map<String, Object> UserData){
        if (UserData.isEmpty()) {
            System.err.println("[ERROR] Skipping invalid packet...");
            return;
        }

        // PROPERLY WRITE THE CODE
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            // Super Table: Packet Metadata
            String insertQuery_DeleteUser = "DELETE INTO User (Username, Password, Role) VALUES (?, ?, ?)"; 
            PreparedStatement stmt_NewUser = conn.prepareStatement(insertQuery_DeleteUser);
            stmt_NewUser.setString(1, (String) UserData.get("Username"));
            stmt_NewUser.setString(2, (String) UserData.get("Password"));
            stmt_NewUser.setString(3, (String) UserData.get("Role"));
             
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    static void ChangeRole(Map<String, Object> UserData) {
        if (UserData.isEmpty()) {
            System.err.println("[ERROR] Skipping invalid packet...");
            return;
        }

        // PROPERLY WRITE THE CODE
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD)) {
            // Super Table: Packet Metadata
            String insertQuery_NewUserRole = "DELETE INTO User (Username, Password, Role) VALUES (?, ?, ?)"; 
            PreparedStatement stmt_NewRole = conn.prepareStatement(insertQuery_NewUserRole);
            stmt_NewRole.setString(1, (String) UserData.get("Username"));
            stmt_NewRole.setString(2, (String) UserData.get("Password"));
            stmt_NewRole.setString(3, (String) UserData.get("Role"));
             
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}
