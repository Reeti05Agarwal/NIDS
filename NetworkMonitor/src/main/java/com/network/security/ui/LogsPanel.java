package com.network.security.ui;

import java.awt.BorderLayout;
import java.awt.Color;

import javax.swing.BorderFactory;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;

/**
 * Simple “Logs” page with static dummy entries. Admin‑only view.
 */
public class LogsPanel extends JPanel {

    public LogsPanel() {
        setLayout(new BorderLayout());
        setBackground(Color.WHITE);
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Column names
        String[] cols = {"Timestamp", "Level", "Message"};

        // Read‑only table model
        DefaultTableModel model = new DefaultTableModel(cols, 0) {
            @Override
            public boolean isCellEditable(int row, int col) {
                return false;
            }
        };

        // Static dummy data
        model.addRow(new Object[]{"2025-04-20 14:50:02", "INFO", "User alice logged in"});
        model.addRow(new Object[]{"2025-04-20 14:52:15", "WARNING", "Failed SSH login from 10.0.0.5"});
        model.addRow(new Object[]{"2025-04-20 14:53:07", "ERROR", "Database connection timeout"});
        model.addRow(new Object[]{"2025-04-20 14:55:30", "DEBUG", "PacketParserBuffer.parsePacket() invoked"});
        model.addRow(new Object[]{"2025-04-20 14:56:44", "CRITICAL", "Possible DDoS attack detected"});

        JTable table = new JTable(model);
        table.setFillsViewportHeight(true);

        // Wrap in a titled border
        JPanel wrapper = new JPanel(new BorderLayout());
        wrapper.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(Color.GRAY),
                "System Logs",
                TitledBorder.LEFT, TitledBorder.TOP
        ));
        wrapper.add(new JScrollPane(table), BorderLayout.CENTER);

        add(wrapper, BorderLayout.CENTER);
    }
}
