package com.network.security.services;

import com.network.security.entity.Role;
import com.network.security.entity.User;

public class UserService {

    public boolean validateLogin(String username, String password) {
        if (username.equals("admin") && password.equals("admin")) {
            return true;
        } else if (username.equals("user") && password.equals("user")) {
            return true;
        }
        return false;
    }

    public User getUser(String username) {
        if (username.equals("admin")) {
            return new User(1, "admin", "", Role.ADMIN);
        } else if (username.equals("user")) {
            return new User(2, "user", "", Role.VIEWER);
        }
        return null;
    }
}
