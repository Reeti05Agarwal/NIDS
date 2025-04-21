package com.network.security.auth;

import java.util.Arrays;
import java.util.List;

/**
 * Administrator gets all three pages.
 */
public class Admin extends Person {

    public Admin(String username) {
        super(username);
    }

    @Override
    public boolean isAdmin() {
        return true;
    }

    @Override
    public List<String> getAccessiblePages() {
        // order matters for how they appear in the sidebar
        return Arrays.asList("Packet Capture", "Logs", "Analytics");
    }
}
