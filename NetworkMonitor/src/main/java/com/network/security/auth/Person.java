package com.network.security.auth;

import java.util.List;

/**
 * Superclass for any “whoever is logged in.” Subclasses decide which pages you
 * get.
 */
public abstract class Person {

    protected final String username;

    public Person(String username) {
        this.username = username;
    }

    public String getUsername() {
        return username;
    }

    /**
     * Am I an administrator?
     */
    public abstract boolean isAdmin();

    /**
     * The list of pages this person should see, in sidebar order. E.g. ["Packet
     * Capture","Logs"] or ["Packet Capture","Logs","Analytics"].
     */
    public abstract List<String> getAccessiblePages();
}
