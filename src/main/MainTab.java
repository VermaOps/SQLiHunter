package main;

import javax.swing.*;
import java.awt.*;

/**
 * Top-level Burp Suite tab that contains:
 *   - Tab 1: Findings (ResultsPanel)
 *   - Tab 2: Settings (SettingsPanel)
 *   - Tab 3: Help
 */
public class MainTab {

    private final JPanel root;

    public MainTab(ResultsPanel resultsPanel, SettingsPanel settingsPanel, 
                   ApiTrafficPanel apiTrafficPanel) {
        root = new JPanel(new BorderLayout());

        JTabbedPane tabs = new JTabbedPane();
        tabs.setFont(tabs.getFont().deriveFont(Font.BOLD, 12f));

        // Create split pane for SQLi Runner tab: API Traffic (left) + Findings (right)
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                apiTrafficPanel.getPanel(), resultsPanel.getPanel());
        splitPane.setResizeWeight(0.4);  // 40% left, 60% right
        splitPane.setContinuousLayout(true);
        splitPane.setBorder(null);
        SwingUtilities.invokeLater(() -> splitPane.setDividerLocation(0.5));
        
        tabs.addTab("SQLi Runner", splitPane);
        tabs.addTab("Settings", settingsPanel.getPanel());

        root.add(tabs, BorderLayout.CENTER);
    }

    public JPanel getComponent() { return root; }
}
