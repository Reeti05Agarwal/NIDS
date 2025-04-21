// src/main/java/com/network/security/ui/SignUpFrame.java
package com.network.security.ui;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;

import com.network.security.auth.PasswordValidationException;
import com.network.security.services.UserService;

public class SignUpFrame extends JFrame {

    private final JTextField usernameField = new JTextField(20);
    private final JTextField emailField = new JTextField(20);
    private final JPasswordField passwordField = new JPasswordField(20);

    private final UserService userService = new UserService();

    public SignUpFrame() {
        super("Sign Up");
        setDefaultCloseOperation(DISPOSE_ON_CLOSE);
        setSize(400, 260);
        setLocationRelativeTo(null);

        JPanel form = new JPanel(new GridBagLayout());
        form.setBorder(BorderFactory.createEmptyBorder(20, 20, 20, 20));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(8, 8, 8, 8);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        gbc.gridy = 0;
        gbc.gridx = 0;
        form.add(new JLabel("Username:"), gbc);
        gbc.gridx = 1;
        form.add(usernameField, gbc);

        gbc.gridy = 1;
        gbc.gridx = 0;
        form.add(new JLabel("Email:"), gbc);
        gbc.gridx = 1;
        form.add(emailField, gbc);

        gbc.gridy = 2;
        gbc.gridx = 0;
        form.add(new JLabel("Password:"), gbc);
        gbc.gridx = 1;
        form.add(passwordField, gbc);

        JButton signUpBtn = new JButton("Sign Up");
        signUpBtn.addActionListener(this::performSignUp);
        gbc.gridy = 3;
        gbc.gridx = 0;
        gbc.gridwidth = 2;
        form.add(signUpBtn, gbc);

        add(form);
    }

    private void performSignUp(ActionEvent e) {
        String user = usernameField.getText().trim();
        String email = emailField.getText().trim();
        String pass = new String(passwordField.getPassword());

        try {
            userService.register(user, email, pass);
            JOptionPane.showMessageDialog(this,
                    "Registration successful!", "Welcome",
                    JOptionPane.INFORMATION_MESSAGE);
            dispose();
        } catch (PasswordValidationException pve) {
            JOptionPane.showMessageDialog(this,
                    pve.getMessage(), "Weak Password",
                    JOptionPane.WARNING_MESSAGE);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this,
                    "Sign‑up failed: " + ex.getMessage(),
                    "Error", JOptionPane.ERROR_MESSAGE);
        }
    }
}
