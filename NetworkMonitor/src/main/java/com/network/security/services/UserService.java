package com.network.security.services;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;

import com.network.security.Dao.UserDao;
import com.network.security.auth.PasswordValidationException;
import com.network.security.entity.Role;
import com.network.security.entity.User;
import com.network.security.util.DBConnection;

/**
 * Service layer for user operations: login, registration, and validations.
 */
public class UserService {

    /**
     * Validates login by checking the stored password hash.
     */
    // public UserService() {
    //     try (Connection conn = DBConnection.getConnection()) {
    //         UserDao dao = new UserDao(conn);
    //         // only seed if "admin" user is missing
    //         if (dao.getUserByUsername("admin") == null) {
    //             // default password: Admin123!  (meets uppercase/lowercase/digit/special requirements)
    //             String defaultPass = "Admin@1";
    //             String hashed = hash(defaultPass);
    //             User admin = new User(0, "admin", "admin@domain.com", hashed, Role.ADMIN);
    //             dao.createUser(admin);
    //             System.out.println("[UserService] Default admin created: admin / Admin@1");
    //         }
    //     } catch (Exception e) {
    //         throw new RuntimeException("Failed to seed default admin", e);
    //     }
    // }
    public boolean validateLogin(String username, String password) throws Exception {
        try (Connection conn = DBConnection.getConnection()) {
            UserDao dao = new UserDao(conn);
            User user = dao.getUserByUsername(username);
            if (user == null) {
                return false;
            }
            return hash(password).equals(user.getPasswordHash());
        }
    }

    /**
     * Fetches the full User object from the DB.
     */
    public User getUser(String username) throws Exception {
        try (Connection conn = DBConnection.getConnection()) {
            return new UserDao(conn).getUserByUsername(username);
        }
    }

    /**
     * Registers a new VIEWER with the given username, email, and password.
     */
    public void register(String username, String email, String password) throws Exception {
        // 1) Email format validation
        validateEmail(email);
        // 2) Password complexity validation
        validatePassword(password);

        String hashed = hash(password);
        User toCreate = new User(0, username, email, hashed, Role.VIEWER);
        try (Connection conn = DBConnection.getConnection()) {
            new UserDao(conn).createUser(toCreate);
        }
    }

    /**
     * Ensures the email matches a standard pattern.
     */
    private void validateEmail(String email) throws PasswordValidationException {
        if (email == null || !email.matches("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$")) {
            throw new PasswordValidationException("Invalid email format. Please enter a valid email address.");
        }
    }

    /**
     * Ensures the password meets complexity requirements.
     */
    private void validatePassword(String pwd) throws PasswordValidationException {
        if (pwd == null || pwd.length() < 4) {
            throw new PasswordValidationException("Password must be at least 4 characters long.");
        }
        if (!pwd.matches(".*[A-Z].*")) {
            throw new PasswordValidationException("Password must contain at least one uppercase letter.");
        }
        if (!pwd.matches(".*[a-z].*")) {
            throw new PasswordValidationException("Password must contain at least one lowercase letter.");
        }
        if (!pwd.matches(".*\\d.*")) {
            throw new PasswordValidationException("Password must contain at least one digit.");
        }
        // special character check, hyphen, bracket, backslash escaped
        if (!pwd.matches(".*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?].*")) {
            throw new PasswordValidationException("Password must contain at least one special character.");
        }
    }

    /**
     * Hashes the password via SHA-256.
     */
    private String hash(String pwd) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(pwd.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : d) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
