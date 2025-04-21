package com.network.security.ui;

import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridLayout;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTextArea;
import javax.swing.JToggleButton;
import javax.swing.JToolBar;
import javax.swing.border.TitledBorder;

import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.data.category.DefaultCategoryDataset;

import com.network.security.auth.AuthManager;
import com.network.security.services.PacketPipelineService;

/**
 * Dashboard – packet capture, analytics & (admin‑only) logs, blacklist, rules.
 */
public class MainFrame extends JFrame {

    private static final int SIDEBAR_WIDTH = 220;
    private static final Dimension BUTTON_SIZE = new Dimension(SIDEBAR_WIDTH - 10, 30);
    private static final Color COLOR_BG = new Color(245, 245, 245);
    private static final Color COLOR_ACCENT = Color.WHITE;
    private static final Color COLOR_HOVER = new Color(220, 220, 220);
    private static final Color COLOR_BORDER = new Color(200, 200, 200);

    private final AuthManager auth;
    private final CardLayout cardLayout = new CardLayout();
    private final JPanel cards = new JPanel(cardLayout);

    public MainFrame(AuthManager auth) {
        super("Network Security Dashboard");
        this.auth = auth;

        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setSize(1024, 768);
        setLocationRelativeTo(null);

        // ── Sidebar ───────────────────────────────────────────────
        JToolBar nav = new JToolBar(JToolBar.VERTICAL);
        nav.setFloatable(false);
        nav.setBackground(COLOR_BG);
        nav.setLayout(new BoxLayout(nav, BoxLayout.Y_AXIS));

        // Everyone gets Packet Capture + Analytics
        addSidebarButton(nav, "Packet Capture");
        addSidebarButton(nav, "Analytics");

        // Admins get extra panels
        if (auth.isAdmin()) {
            addSidebarButton(nav, "Logs");
            addSidebarButton(nav, "Blocked IPs");
            addSidebarButton(nav, "Rules Overview");
        }

        // ── Content cards ────────────────────────────────────────
        cards.setBackground(COLOR_BG);
        cards.add(createPacketCapturePanel(), "Packet Capture");
        cards.add(createAnalyticsPanel(), "Analytics");

        if (auth.isAdmin()) {
            cards.add(new LogsPanel(), "Logs");
            cards.add(new BlockedIPPanel(), "Blocked IPs");
            cards.add(new RulesOverviewPanel(), "Rules Overview");
        }

        JSplitPane split = new JSplitPane(
                JSplitPane.HORIZONTAL_SPLIT,
                nav, cards
        );
        split.setDividerLocation(SIDEBAR_WIDTH);
        split.setOneTouchExpandable(true);
        add(split, BorderLayout.CENTER);

        // ── Header / Logout ─────────────────────────────────────
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

    private void addSidebarButton(JToolBar bar, String caption) {
        JButton b = new JButton(caption);
        b.setMaximumSize(BUTTON_SIZE);
        b.setBackground(COLOR_ACCENT);
        b.setBorder(BorderFactory.createLineBorder(COLOR_BORDER));
        b.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseEntered(java.awt.event.MouseEvent e) {
                b.setBackground(COLOR_HOVER);
            }

            public void mouseExited(java.awt.event.MouseEvent e) {
                b.setBackground(COLOR_ACCENT);
            }
        });
        b.addActionListener(e -> cardLayout.show(cards, caption));
        bar.add(Box.createVerticalStrut(10));
        bar.add(b);
    }

    // ── Packet Capture Panel ──────────────────────────────────
    private JPanel createPacketCapturePanel() {
        JPanel p = new JPanel(new BorderLayout(5, 5));
        p.setBackground(COLOR_BG);
        p.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JTextArea out = new JTextArea();
        out.setEditable(false);

        JToggleButton toggle = new JToggleButton("Start");
        toggle.setPreferredSize(BUTTON_SIZE);
        toggle.addActionListener(e -> {
            if (toggle.isSelected()) {
                PacketPipelineService.running = true;
                new Thread(() -> PacketPipelineService.main(new String[0])).start();
                out.setText("Pipeline started...\n");
                toggle.setText("Stop");
            } else {
                PacketPipelineService.running = false;
                out.append("Pipeline stopped.\n");
                toggle.setText("Start");
            }
        });

        JPanel ctrl = new JPanel(new FlowLayout(FlowLayout.LEFT));
        ctrl.setBackground(COLOR_BG);
        ctrl.add(toggle);

        p.add(ctrl, BorderLayout.NORTH);
        p.add(new JScrollPane(out), BorderLayout.CENTER);
        return p;
    }

    // ── Analytics Panel ───────────────────────────────────────
    private JPanel createAnalyticsPanel() {
        JPanel grid = new JPanel(new GridLayout(2, 2, 10, 10));
        grid.setBackground(COLOR_BG);
        grid.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        grid.add(makeChartCard("Real‑Time Traffic"));
        grid.add(makeChartCard("Suspicious Activity"));
        grid.add(makeChartCard("Top Malicious IP"));
        grid.add(makeChartCard("Anomaly Detection"));
        return grid;
    }

    private JPanel makeChartCard(String title) {
        DefaultCategoryDataset ds = new DefaultCategoryDataset();
        ds.addValue(0, "Value", "X");  // placeholder, to be replaced with real data
        ChartPanel chart = new ChartPanel(
                ChartFactory.createBarChart(
                        title, "Category", "Count",
                        ds, PlotOrientation.VERTICAL,
                        false, true, false
                )
        );
        JPanel wrap = new JPanel(new BorderLayout());
        wrap.setBackground(COLOR_BG);
        wrap.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createLineBorder(COLOR_BORDER),
                title, TitledBorder.LEFT, TitledBorder.TOP
        ));
        wrap.add(chart, BorderLayout.CENTER);
        return wrap;
    }
}
