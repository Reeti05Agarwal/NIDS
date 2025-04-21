package com.network.security.auth;

import java.util.Arrays;
import java.util.List;

/**
 * Regular (non‑admin) user only gets basic pages.
 */
public class RegularUser extends Person {

    public RegularUser(String username) {
        super(username);
    }

    @Override
    public boolean isAdmin() {
        return false;
    }

    @Override
    public List<String> getAccessiblePages() {
        return Arrays.asList("Packet Capture", "Logs");
    }
}
