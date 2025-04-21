package com.network.security.ui;

import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import javax.swing.DefaultCellEditor;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumn;

import com.network.security.util.DBConnection;

/**
 * Editable overview of all five rule tables: • ddos_rules • brute_force_rules •
 * dpi_rules • dns_web_filtering_rules • insider_threat_rules
 *
 * Columns: 0: ID (PK, must type for new rows) 1: Table name (combo box) 2:
 * Rule / Name 3: Threshold 4: Window / Extra 5: Severity / Details
 */
public class RulesOverviewPanel extends JPanel {

    // column indices
    private static final int COL_ID = 0;
    private static final int COL_TABLE = 1;
    private static final int COL_NAME = 2;
    private static final int COL_THRES = 3;
    private static final int COL_WIN = 4;
    private static final int COL_EXTRA = 5;

    private final String[] tables = {
        "ddos_rules",
        "brute_force_rules",
        "dpi_rules",
        "dns_web_filtering_rules",
        "insider_threat_rules"
    };

    private final DefaultTableModel model;
    private final JTable table;

    public RulesOverviewPanel() {
        super(new BorderLayout());

        // 1) Table model
        model = new DefaultTableModel(
                new String[]{"ID", "Table", "Rule / Name",
                    "Threshold", "Window / Extra", "Severity / Details"},
                0
        ) {
            @Override
            public boolean isCellEditable(int row, int col) {
                // ID only editable if blank (new row), rest always editable
                if (col == COL_ID) {
                    Object v = getValueAt(row, COL_ID);
                    return v == null || v.toString().isBlank();
                }
                return true;
            }

            @Override
            public Class<?> getColumnClass(int col) {
                return col == COL_ID ? Integer.class : String.class;
            }
        };

        // 2) JTable + combo‑box for “Table” column
        table = new JTable(model);
        table.setFillsViewportHeight(true);
        TableColumn tc = table.getColumnModel().getColumn(COL_TABLE);
        tc.setCellEditor(new DefaultCellEditor(new JComboBox<>(tables)));

        add(new JScrollPane(table), BorderLayout.CENTER);

        // 3) Buttons: Add, Reload, Save
        JPanel btns = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton addRow = new JButton("Add Row"),
                reload = new JButton("Reload"),
                save = new JButton("Save");
        btns.add(addRow);
        btns.add(reload);
        btns.add(save);
        add(btns, BorderLayout.SOUTH);

        addRow.addActionListener(e -> {
            model.addRow(new Object[]{null, tables[0], "", "", "", ""});
            int r = model.getRowCount() - 1;
            table.requestFocusInWindow();
            table.changeSelection(r, COL_ID, false, false);
            table.editCellAt(r, COL_ID);
        });
        reload.addActionListener(e -> loadAll());
        save.addActionListener(e -> saveAll());

        // initial data load
        loadAll();
    }

    private void loadAll() {
        model.setRowCount(0);
        // SELECTs for each table
        String[] selects = {
            "SELECT id, attack_type, packet_threshold, time_window_sec, severity_level FROM ddos_rules",
            "SELECT id, service, failed_attempt_threshold, time_window_sec, rule_id           FROM brute_force_rules",
            "SELECT id, rule_name, payload_length_threshold, NULL             , check_encryption FROM dpi_rules",
            "SELECT id, rule_type, threshold             , time_window_seconds, pattern         FROM dns_web_filtering_rules",
            "SELECT id, rule_name, access_threshold      , time_window_sec     , rule_type       FROM insider_threat_rules"
        };

        try (Connection c = DBConnection.getConnection()) {
            for (int i = 0; i < tables.length; i++) {
                try (PreparedStatement ps = c.prepareStatement(selects[i]); ResultSet rs = ps.executeQuery()) {

                    while (rs.next()) {
                        model.addRow(new Object[]{
                            rs.getInt(1),
                            tables[i],
                            rs.getString(2),
                            rs.getString(3) != null ? rs.getString(3) : "",
                            rs.getString(4) != null ? rs.getString(4) : "",
                            rs.getString(5) != null ? rs.getString(5) : ""
                        });
                    }
                }
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            JOptionPane.showMessageDialog(this,
                    "Error loading rules:\n" + ex.getMessage(),
                    "Load Error", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void saveAll() {
        if (table.isEditing()) {
            table.getCellEditor().stopCellEditing();
        }

        try (Connection c = DBConnection.getConnection()) {
            c.setAutoCommit(false);

            for (int row = 0; row < model.getRowCount(); row++) {
                // gather user input
                Object idObj = model.getValueAt(row, COL_ID);
                String tbl = model.getValueAt(row, COL_TABLE).toString();
                String name = model.getValueAt(row, COL_NAME).toString();
                String thres = model.getValueAt(row, COL_THRES).toString();
                String win = model.getValueAt(row, COL_WIN).toString();
                String extra = model.getValueAt(row, COL_EXTRA).toString();

                if (idObj == null || idObj.toString().isBlank()) {
                    JOptionPane.showMessageDialog(this,
                            "Row " + (row + 1) + ": Please supply an ID.",
                            "Validation Error", JOptionPane.WARNING_MESSAGE);
                    continue;
                }
                int id = Integer.parseInt(idObj.toString());

                // perform UPDATE; if it affects 0 rows, do INSERT
                int updated = 0;
                switch (tbl) {

                    case "ddos_rules" -> {
                        // UPDATE
                        try (PreparedStatement ps = c.prepareStatement(
                                "UPDATE ddos_rules SET attack_type=?, packet_threshold=?, time_window_sec=?, severity_level=? WHERE id=?"
                        )) {
                            ps.setString(1, name);
                            ps.setString(2, thres);
                            ps.setString(3, win);
                            ps.setString(4, extra);
                            ps.setInt(5, id);
                            updated = ps.executeUpdate();
                        }
                        if (updated == 0) {
                            try (PreparedStatement ins = c.prepareStatement(
                                    "INSERT INTO ddos_rules(id,attack_type,packet_threshold,time_window_sec,severity_level) VALUES(?,?,?,?,?)"
                            )) {
                                ins.setInt(1, id);
                                ins.setString(2, name);
                                ins.setString(3, thres);
                                ins.setString(4, win);
                                ins.setString(5, extra);
                                ins.executeUpdate();
                            }
                        }
                    }

                    case "brute_force_rules" -> {
                        try (PreparedStatement ps = c.prepareStatement(
                                "UPDATE brute_force_rules SET service=?, failed_attempt_threshold=?, time_window_sec=?, rule_id=? WHERE id=?"
                        )) {
                            ps.setString(1, name);
                            ps.setString(2, thres);
                            ps.setString(3, win);
                            ps.setString(4, extra);
                            ps.setInt(5, id);
                            updated = ps.executeUpdate();
                        }
                        if (updated == 0) {
                            try (PreparedStatement ins = c.prepareStatement(
                                    "INSERT INTO brute_force_rules(id,service,failed_attempt_threshold,time_window_sec,rule_id) VALUES(?,?,?,?,?)"
                            )) {
                                ins.setInt(1, id);
                                ins.setString(2, name);
                                ins.setString(3, thres);
                                ins.setString(4, win);
                                ins.setString(5, extra);
                                ins.executeUpdate();
                            }
                        }
                    }

                    case "dpi_rules" -> {
                        // ensure check_encryption is at most 1 char
                        String chk = extra;
                        if (chk.length() > 1) {
                            chk = chk.substring(0, 1);
                        }

                        try (PreparedStatement ps = c.prepareStatement(
                                "UPDATE dpi_rules SET rule_name=?, payload_length_threshold=?, check_encryption=? WHERE id=?"
                        )) {
                            ps.setString(1, name);
                            ps.setString(2, thres);
                            ps.setString(3, chk);
                            ps.setInt(4, id);
                            updated = ps.executeUpdate();
                        }
                        if (updated == 0) {
                            try (PreparedStatement ins = c.prepareStatement(
                                    "INSERT INTO dpi_rules(id,rule_name,payload_length_threshold,check_encryption) VALUES(?,?,?,?)"
                            )) {
                                ins.setInt(1, id);
                                ins.setString(2, name);
                                ins.setString(3, thres);
                                ins.setString(4, chk);
                                ins.executeUpdate();
                            }
                        }
                    }

                    case "dns_web_filtering_rules" -> {
                        try (PreparedStatement ps = c.prepareStatement(
                                "UPDATE dns_web_filtering_rules SET rule_type=?, threshold=?, time_window_seconds=?, pattern=? WHERE id=?"
                        )) {
                            ps.setString(1, name);
                            ps.setString(2, thres);
                            ps.setString(3, win);
                            ps.setString(4, extra);
                            ps.setInt(5, id);
                            updated = ps.executeUpdate();
                        }
                        if (updated == 0) {
                            try (PreparedStatement ins = c.prepareStatement(
                                    "INSERT INTO dns_web_filtering_rules(id,rule_type,threshold,time_window_seconds,pattern) VALUES(?,?,?,?,?)"
                            )) {
                                ins.setInt(1, id);
                                ins.setString(2, name);
                                ins.setString(3, thres);
                                ins.setString(4, win);
                                ins.setString(5, extra);
                                ins.executeUpdate();
                            }
                        }
                    }

                    case "insider_threat_rules" -> {
                        try (PreparedStatement ps = c.prepareStatement(
                                "UPDATE insider_threat_rules SET rule_name=?, access_threshold=?, time_window_sec=?, rule_type=? WHERE id=?"
                        )) {
                            ps.setString(1, name);
                            ps.setString(2, thres);
                            ps.setString(3, win);
                            ps.setString(4, extra);
                            ps.setInt(5, id);
                            updated = ps.executeUpdate();
                        }
                        if (updated == 0) {
                            try (PreparedStatement ins = c.prepareStatement(
                                    "INSERT INTO insider_threat_rules(id,rule_name,access_threshold,time_window_sec,rule_type) VALUES(?,?,?,?,?)"
                            )) {
                                ins.setInt(1, id);
                                ins.setString(2, name);
                                ins.setString(3, thres);
                                ins.setString(4, win);
                                ins.setString(5, extra);
                                ins.executeUpdate();
                            }
                        }
                    }
                } // end switch

            } // end for

            c.commit();
            JOptionPane.showMessageDialog(this,
                    "All changes saved successfully.",
                    "Success", JOptionPane.INFORMATION_MESSAGE);
            loadAll();

        } catch (Exception ex) {
            ex.printStackTrace();
            JOptionPane.showMessageDialog(this,
                    "Error saving:\n" + ex.getMessage(),
                    "Save Error", JOptionPane.ERROR_MESSAGE);
        }
    }
}
