package com.network.security.auth;

import com.network.security.entity.User;
import com.network.security.services.UserService;

public class AuthManager {
    private final UserService userService;
    private User loggedInUser = null;

    public AuthManager(UserService userService) {
        this.userService = userService;
    }

    public boolean login(String username, String password) throws Exception {
        boolean isValid = userService.validateLogin(username, password);
        if (isValid) {
            loggedInUser = userService.getUser(username);
        }
        return isValid;
    }

    public void logout() {
        loggedInUser = null;
    }

    public User getLoggedInUser() {
        return loggedInUser;
    }

    public boolean isAdmin() {
        return loggedInUser != null && loggedInUser.getRole().toString().equals("ADMIN");
    }
}
