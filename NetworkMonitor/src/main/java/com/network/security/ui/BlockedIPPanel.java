package com.network.security.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.util.List;

import javax.swing.BorderFactory;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.border.TitledBorder;

import com.network.security.services.BlacklistService;

/**
 * Panel that displays all currently blocked IP addresses.
 */
public class BlockedIPPanel extends JPanel {

    public BlockedIPPanel() {
        setLayout(new BorderLayout());
        setBackground(Color.WHITE);
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Use service to fetch the blocked IPs
        List<String> ips = new BlacklistService().getAllBlockedIPs();

        // Show them in a JList
        JList<String> list = new JList<>(ips.toArray(new String[0]));
        list.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(Color.GRAY),
                "Blocked IP Addresses",
                TitledBorder.LEFT, TitledBorder.TOP
        ));

        add(new JScrollPane(list), BorderLayout.CENTER);
    }
}
