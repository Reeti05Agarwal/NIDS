package com.network.security.ui;

import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.List;
import java.util.Map;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.JToggleButton;
import javax.swing.JToolBar;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.border.TitledBorder;

import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.data.category.DefaultCategoryDataset;
import org.jfree.data.general.DefaultPieDataset;
import org.jfree.data.xy.XYSeries;
import org.jfree.data.xy.XYSeriesCollection;

import com.network.security.Dao.AlertDao;
import com.network.security.Dao.AnalyticsDao;
import com.network.security.Dao.BlacklistDao;
import com.network.security.PacketSniffing.PacketSnifferService;
import com.network.security.auth.AuthManager;

/*
 * Sidebar Navigation
 * Dynamic Panels (CardLayout)
 * Admin-Only Views
 * Packet Capture Controls
 * Analytics with JFreeChart Visualizations
 * Blocked IP View
 */

/**
 * Dashboard – packet capture, analytics, rules & logs (admin‑only).
 */
public class MainFrame extends JFrame {

    // ─── Look & feel ────────────────────────────────────────────────
    private static final int SIDEBAR_WIDTH = 220;
    private static final Dimension BUTTON_SIZE
            = new Dimension(SIDEBAR_WIDTH - 10, 30);
    private static final Color COLOR_BG = new Color(245, 245, 245);
    private static final Color COLOR_ACCENT = Color.WHITE;
    private static final Color COLOR_HOVER = new Color(220, 220, 220);
    private static final Color COLOR_BORDER = new Color(200, 200, 200);

    // ─── services / dao ─────────────────────────────────────────────
    private final PacketSnifferService snifferService = new PacketSnifferService();
    private final AnalyticsDao analyticsDao = new AnalyticsDao();
    private final AlertDao alertDao = new AlertDao();

    // ─── layout ─────────────────────────────────────────────────────
    private final CardLayout card = new CardLayout();
    private final JPanel cards = new JPanel(card);

    public MainFrame(AuthManager auth) {
        super("Network Security Dashboard");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setSize(1024, 768);
        setLocationRelativeTo(null);

        /* ── sidebar ──────────────────────────────────────────────── */
        JToolBar nav = new JToolBar(JToolBar.VERTICAL);
        nav.setFloatable(false);
        nav.setBackground(COLOR_BG);
        nav.setLayout(new BoxLayout(nav, BoxLayout.Y_AXIS));

        addSidebarButton(nav, "Packet Capture");
        addSidebarButton(nav, "Analytics");

        if (auth.isAdmin()) {
            addSidebarButton(nav, "Blocked IPs");
            addSidebarButton(nav, "Rules Overview");
            addSidebarButton(nav, "Logs");
        }

        /* ── cards ────────────────────────────────────────────────── */
        cards.setBackground(COLOR_BG);
        cards.add(createPacketCapturePanel(), "Packet Capture");
        cards.add(createAnalyticsPanel(), "Analytics");

        if (auth.isAdmin()) {
            cards.add(createBlockedIPPanel(), "Blocked IPs");
            cards.add(new RulesOverviewPanel(), "Rules Overview");
            cards.add(new LogsPanel(), "Logs");
        }

        JSplitPane split = new JSplitPane(
                JSplitPane.HORIZONTAL_SPLIT, nav, cards);
        split.setDividerLocation(SIDEBAR_WIDTH);
        split.setOneTouchExpandable(true);
        add(split, BorderLayout.CENTER);

        /* ── header / logout ──────────────────────────────────────── */
        JPanel header = new JPanel(new BorderLayout());
        header.setBackground(COLOR_BG);
        header.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));
        JButton logout = new JButton("Logout");
        logout.setPreferredSize(BUTTON_SIZE);
        logout.addActionListener(e -> {
            auth.logout();
            new LoginFrame(auth).setVisible(true);
            dispose();
        });
        header.add(logout, BorderLayout.EAST);
        add(header, BorderLayout.NORTH);
    }

    /* ==============================================================
       sidebar helper
       ============================================================== */
    private void addSidebarButton(JToolBar bar, String caption) {
        JButton b = new JButton(caption);
        b.setMaximumSize(BUTTON_SIZE);
        b.setBackground(COLOR_ACCENT);
        b.setBorder(BorderFactory.createLineBorder(COLOR_BORDER));
        b.addMouseListener(new MouseAdapter() {
            public void mouseEntered(MouseEvent e) {
                b.setBackground(COLOR_HOVER);
            }

            public void mouseExited(MouseEvent e) {
                b.setBackground(COLOR_ACCENT);
            }
        });
        b.addActionListener(e -> card.show(cards, caption));
        bar.add(Box.createVerticalStrut(10));
        bar.add(b);
    }

    /* ==============================================================
       Packet capture
       ============================================================== */
    private JPanel createPacketCapturePanel() {
    JPanel p = new JPanel(new BorderLayout(5, 5));
    p.setBackground(COLOR_BG);
    p.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

    JTextArea out = new JTextArea();
    out.setEditable(false);
    out.setLineWrap(true);
    out.setWrapStyleWord(true);

    JToggleButton toggle = new JToggleButton("Start");
    toggle.setPreferredSize(BUTTON_SIZE);

    JPanel ctrl = new JPanel(new FlowLayout(FlowLayout.LEFT));
    ctrl.setBackground(COLOR_BG);
    ctrl.add(toggle);

    p.add(ctrl, BorderLayout.NORTH);
    p.add(new JScrollPane(out), BorderLayout.CENTER);

    toggle.addActionListener(e -> {
        if (toggle.isSelected()) {
            toggle.setText("Stop");

            // Start capturing packets and displaying them in the text area
            new Thread(() -> snifferService.startCapturing(packetInfo -> {
                SwingUtilities.invokeLater(() -> {
                    out.append(packetInfo + "\n");
                });
            }), "pcap").start();

            out.setText("Packet capture started…\n");

        } else {
            toggle.setText("Start");
            snifferService.stopCapturing();
            out.append("Packet capture stopped.\n");
        }
    });

    return p;
}


    /* ==============================================================
       Analytics grid (3×3)
       ============================================================== */
    private JPanel createAnalyticsPanel() {
        JPanel grid = new JPanel(new GridLayout(3, 3, 10, 10));
        grid.setBackground(COLOR_BG);
        grid.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        grid.add(chartCard(createRealTimeTrafficChart(), "Real‑Time Traffic"));
        grid.add(chartCard(createSuspiciousActivityChart(), "Suspicious Activity"));
        grid.add(chartCard(createTopMaliciousIPChart(), "Top Malicious IP"));
        grid.add(chartCard(createAnomalyDetectionChart(), "Anomaly Detection"));
        grid.add(chartCard(createGeolocationMapChart(), "Geolocation"));
        grid.add(chartCard(createPortActivityChart(), "Port Activity"));
        grid.add(chartCard(createAttackTrendsChart(), "Attack Trends"));
        grid.add(chartCard(createAttackedServicesChart(), "Attacked Services"));
        grid.add(chartCard(createProtocolAnomalyChart(), "Protocol Anomaly"));
        return grid;
    }

    /* ==============================================================
       Blocked IPs  (admin‑only)
       ============================================================== */
    private JPanel createBlockedIPPanel() {
        JPanel p = new JPanel(new BorderLayout());
        p.setBackground(COLOR_BG);
        p.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        List<String> ips;
        try {
            ips = new BlacklistDao().getAllBlockedIPs();
        } catch (Exception ex) {
            ex.printStackTrace();
            ips = java.util.List.of("Error: " + ex.getMessage());
        }

        JList<String> list = new JList<>(ips.toArray(new String[0]));
        list.setFont(new Font("Monospaced", Font.PLAIN, 12));
        list.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(COLOR_BORDER, 2),
                "Blocked IP Addresses",
                TitledBorder.LEFT, TitledBorder.TOP));
        p.add(new JScrollPane(list), BorderLayout.CENTER);
        return p;
    }

    /* ==============================================================
       Chart helpers
       ============================================================== */
    private JPanel chartCard(JPanel chart, String title) {
        JPanel wrap = new JPanel(new BorderLayout());
        wrap.setBackground(COLOR_BG);
        wrap.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(COLOR_BORDER, 2),
                title, TitledBorder.LEFT, TitledBorder.TOP));
        wrap.add(chart, BorderLayout.CENTER);
        return wrap;
    }

    /* -------- individual charts (unchanged logic) ---------------- */
    private JPanel createRealTimeTrafficChart() {
        /* same as before */
        var ds = new DefaultCategoryDataset();
        try {
            Map<String, Integer> c = alertDao.getAlertCountsBySeverity();
            ds.addValue(c.values().stream().mapToInt(i -> i).sum(), "Alerts/min", "Last 1m");
        } catch (Exception ex) {
            ds.addValue(0, "Error", ex.getMessage());
        }
        return new ChartPanel(ChartFactory.createBarChart(
                "Real‑Time Traffic", "Window", "Alerts", ds,
                PlotOrientation.VERTICAL, false, true, false));
    }

    private JPanel createSuspiciousActivityChart() {
        /* … */
        var ds = new DefaultPieDataset();
        try {
            alertDao.getAlertCountsBySeverity().forEach(ds::setValue);
        } catch (Exception ex) {
            ds.setValue("Error", 1);
        }
        return new ChartPanel(ChartFactory.createPieChart(
                "Suspicious Activity", ds, false, true, false));
    }

    private JPanel createTopMaliciousIPChart() {
        /* … */
        var ds = new DefaultCategoryDataset();
        try {
            analyticsDao.topMaliciousIps(10).forEach((ip, c) -> ds.addValue(c, "Alerts", ip));
        } catch (Exception ex) {
            ds.addValue(0, "Error", ex.getMessage());
        }
        return new ChartPanel(ChartFactory.createBarChart(
                "Top Malicious IP", "IP", "Alerts", ds,
                PlotOrientation.VERTICAL, false, true, false));
    }

    private JPanel createAnomalyDetectionChart() {
        /* … */
        var s = new XYSeries("Score");
        s.add(1, 0.1);
        s.add(2, 0.4);
        s.add(3, 0.2);
        s.add(4, 0.7);
        return new ChartPanel(ChartFactory.createScatterPlot(
                "Anomaly Detection", "t", "score",
                new XYSeriesCollection(s),
                PlotOrientation.VERTICAL, false, true, false));
    }

    private JPanel createGeolocationMapChart() {
        JPanel p = new JPanel(new BorderLayout());
        p.setBackground(COLOR_BG);
        p.add(new JLabel("World‑map placeholder", SwingConstants.CENTER), BorderLayout.CENTER);
        return p;
    }

    private JPanel createPortActivityChart() {
        /* … */
        var ds = new DefaultCategoryDataset();
        try {
            analyticsDao.portActivity(10).forEach((port, c) -> ds.addValue(c, "Attempts", "Port " + port));
        } catch (Exception ex) {
            ds.addValue(0, "Error", ex.getMessage());
        }
        return new ChartPanel(ChartFactory.createStackedBarChart(
                "Port Activity", "Port", "Attempts", ds,
                PlotOrientation.VERTICAL, false, true, false));
    }

    private JPanel createAttackTrendsChart() {
        /* … */
        var s = new XYSeries("Attacks");
        s.add(1, 5);
        s.add(2, 8);
        s.add(3, 6);
        s.add(4, 10);
        return new ChartPanel(ChartFactory.createXYLineChart(
                "Attack Trends", "t(h)", "cnt",
                new XYSeriesCollection(s),
                PlotOrientation.VERTICAL, false, true, false));
    }

    private JPanel createAttackedServicesChart() {
        /* … */
        var ds = new DefaultCategoryDataset();
        try {
            analyticsDao.attackedServices(10).forEach((svc, c) -> ds.addValue(c, "Hits", svc));
        } catch (Exception ex) {
            ds.addValue(0, "Error", ex.getMessage());
        }
        return new ChartPanel(ChartFactory.createStackedBarChart(
                "Attacked Services", "Service", "Hits", ds,
                PlotOrientation.VERTICAL, false, true, false));
    }

    private JPanel createProtocolAnomalyChart() {
        /* … */
        var s = new XYSeries("Anom");
        s.add(1, 0.2);
        s.add(2, 0.5);
        s.add(3, 0.3);
        s.add(4, 0.8);
        return new ChartPanel(ChartFactory.createXYLineChart(
                "Protocol Anomaly", "idx", "score",
                new XYSeriesCollection(s),
                PlotOrientation.VERTICAL, false, true, false));
    }
}
