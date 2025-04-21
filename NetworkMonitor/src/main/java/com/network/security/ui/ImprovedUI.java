// ImprovedUI.java
package com.network.security.ui;

import javax.swing.SwingUtilities;
import javax.swing.UIManager;

import com.formdev.flatlaf.FlatLightLaf;
import com.network.security.auth.AuthManager;
import com.network.security.services.UserService;

public class ImprovedUI {

    public static void main(String[] args) {
        // Use the FlatLaf light theme
        try {
            UIManager.setLookAndFeel(new FlatLightLaf());
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        SwingUtilities.invokeLater(() -> {
            UserService userService = new UserService();
            AuthManager authManager = new AuthManager(userService);
            new LoginFrame(authManager).setVisible(true);
        });
    }
}
