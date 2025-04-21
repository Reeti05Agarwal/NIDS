// src/main/java/com/network/security/auth/AuthManager.java
package com.network.security.auth;

import com.network.security.entity.Role;
import com.network.security.entity.User;
import com.network.security.services.LogService;
import com.network.security.services.UserService;

public class AuthManager {

    private final UserService userService;
    private final LogService logService = new LogService();
    private User loggedInUser = null;

    public AuthManager(UserService userService) {
        this.userService = userService;
    }

    /**
     * Attempts to log in. If successful, records a LOGIN event.
     */
    public boolean login(String username, String password) throws Exception {
        boolean isValid = userService.validateLogin(username, password);
        if (isValid) {
            loggedInUser = userService.getUser(username);
            // Record the login event
            logService.logEvent(
                    loggedInUser.getUsername(),
                    loggedInUser.getRole().name(),
                    "LOGIN"
            );
        }
        return isValid;
    }

    /**
     * Logs out the current user, recording a LOGOUT event if someone was logged
     * in.
     */
    public void logout() {
        if (loggedInUser != null) {
            logService.logEvent(
                    loggedInUser.getUsername(),
                    loggedInUser.getRole().name(),
                    "LOGOUT"
            );
            loggedInUser = null;
        }
    }

    /**
     * Returns the currently logged‑in User, or null if none.
     */
    public User getLoggedInUser() {
        return loggedInUser;
    }

    /**
     * Shortcut to check if the current user has ADMIN role.
     */
    public boolean isAdmin() {
        return loggedInUser != null && loggedInUser.getRole() == Role.ADMIN;
    }
}
