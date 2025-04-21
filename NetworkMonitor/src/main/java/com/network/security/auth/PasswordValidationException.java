package com.network.security.auth;

/**
 * Thrown when a password does not meet the required complexity rules.
 */
public class PasswordValidationException extends Exception {

    public PasswordValidationException(String message) {
        super(message);
    }
}
