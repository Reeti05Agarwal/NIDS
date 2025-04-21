// src/main/java/com/network/security/ui/LogsPanel.java
package com.network.security.ui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.util.List;

import javax.swing.BorderFactory;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.border.TitledBorder;
import javax.swing.table.DefaultTableModel;

import com.network.security.entity.LogEntry;
import com.network.security.services.LogService;

public class LogsPanel extends JPanel {

    public LogsPanel() {
        setLayout(new BorderLayout());
        setBackground(Color.WHITE);
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Column names
        String[] cols = {"ID", "Username", "Role", "Event", "Time"};
        DefaultTableModel model = new DefaultTableModel(cols, 0) {
            @Override
            public boolean isCellEditable(int r, int c) {
                return false;
            }
        };

        // Fetch from DB
        LogService logService = new LogService();
        List<LogEntry> entries = logService.getAllLogs();
        for (LogEntry e : entries) {
            model.addRow(new Object[]{
                e.getId(),
                e.getUsername(),
                e.getRole(),
                e.getEvent(),
                e.getEventTime()
            });
        }

        JTable table = new JTable(model);
        table.setFillsViewportHeight(true);

        JPanel wrapper = new JPanel(new BorderLayout());
        wrapper.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(Color.GRAY),
                "User Login/Logout Logs",
                TitledBorder.LEFT, TitledBorder.TOP
        ));
        wrapper.add(new JScrollPane(table), BorderLayout.CENTER);

        add(wrapper, BorderLayout.CENTER);
    }
}
