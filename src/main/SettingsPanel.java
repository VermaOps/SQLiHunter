package main;

import javax.swing.*;
import javax.swing.border.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import ai.OllamaProvider;
import ai.OpenAIProvider;
import ai.ClaudeProvider;
import javax.swing.SwingWorker;

/**
 * Settings tab — lets users tweak all scan parameters without code changes.
 * Fully theme-aware - respects Burp's native dark/light theme.
 */
public class SettingsPanel {

    private final ScanConfig config;
    private JPanel rootPanel;
    private JTextArea taHiddenParams;
    private Runnable onAIProviderChanged;

    // ── SCAN TYPE radios ──────────────────────────────────────────────────
    private JRadioButton rbAutomated;
    private JRadioButton rbCustom;

    // ── Checkboxes: payload types ─────────────────────────────────────────
    private JCheckBox cbError, cbBoolean, cbTime, cbUnion;

    // ── Checkboxes: target areas ──────────────────────────────────────────
    private JCheckBox cbUrl, cbBody, cbHeaders, cbCookies, cbJson, cbXml, cbHidden;

    // ── Checkboxes: HTTP methods (UI mockup only) ──────────────────────────
    private JCheckBox cbHttpGet, cbHttpPost, cbHttpPut, cbHttpPatch, cbHttpDelete, cbExcludeOptions;

    // ── Traffic source checkboxes (toolbar) ────────────────────────────────
    private JCheckBox cbProxyHistory, cbScopeFilter, cbRepeater;

    // ── Spinners ──────────────────────────────────────────────────────────
    private JSpinner spDelay, spTimeout, //spThreads,
                     spConfidence, spTimingMult, spSleepSec;

    // ── Text areas ────────────────────────────────────────────────────────
    private JTextArea taExcludedParams, taExcludedPaths,
                      taErrorSigs, taCustomPayloads;

    // ── Database Type ─────────────────────────────────────────────────────
    private JComboBox<String> dbTypeCombo;

    // ── AI components ─────────────────────────────────────────────────────
    private JComboBox<String> providerCombo;
    private JTextField endpointField;
    private JPasswordField apiKeyField;
    private JTextField modelField;
    private DefaultListModel<String> modelListModel;
    private JLabel testStatusLabel;
    private JLabel modelNoteLabel;
    private JTextArea statusArea;
    private Runnable onSettingsApplied;
    private JButton newReleasesBtn;
    
    public SettingsPanel(ScanConfig config) {
        this.config = config;
        buildUI();
    }
    
    public void setOnSettingsApplied(Runnable callback) {
        this.onSettingsApplied = callback;
    }

    public void setOnAIProviderChanged(Runnable callback) {
        this.onAIProviderChanged = callback;
    }

    public JPanel getPanel() { return rootPanel; }

    // ── UI construction ───────────────────────────────────────────────────

    private void buildUI() {
        rootPanel = new JPanel(new BorderLayout());
        rootPanel.setBackground(null);

        // Toolbar
        JPanel toolbar = buildToolbar();
        rootPanel.add(toolbar, BorderLayout.NORTH);

        // Main content with 2-column grid
        JPanel content = new JPanel(new GridBagLayout());
        content.setBorder(new EmptyBorder(10, 14, 14, 14));
        content.setBackground(null);

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(0, 0, 12, 12);
        gbc.anchor = GridBagConstraints.NORTHWEST;
        gbc.fill = GridBagConstraints.BOTH;

        /// Row 0: AI Config (col 0) | Exclusions (col 1) | Status (col 2)
        gbc.weightx = 0.34;
        gbc.weighty = 0;
        gbc.gridx = 0; gbc.gridy = 0;
        gbc.gridwidth = 1;
        content.add(buildAIConfigurationSection(), gbc);
        gbc.weightx = 0.33;
        gbc.gridx = 1;
        content.add(buildExclusionsSection(), gbc);
        gbc.weightx = 0.33;
        gbc.gridx = 2;
        content.add(buildStatusSection(), gbc);

        // Row 1: SCAN TYPE (full width - spans both columns)
        gbc.weightx = 1.0;
        gbc.weighty = 0;
        gbc.gridx = 0; gbc.gridy = 1;
        gbc.gridwidth = 3;
        content.add(buildScanTypeSection(), gbc);

        // Row 2: Target Areas (col 0) | Error Signatures (col 1) | Hidden Parameters (col 2)
        // First, reset gridwidth and create a new panel for 3-column layout
        gbc.gridwidth = 1;
        gbc.weightx = 0.34;
        gbc.weighty = 0.5;
        gbc.gridx = 0; gbc.gridy = 2;
        content.add(buildTargetAreasSection(), gbc);
        gbc.weightx = 0.33;
        gbc.gridx = 1;
        content.add(buildErrorSigsSection(), gbc);
        gbc.weightx = 0.33;
        gbc.gridx = 2;
        content.add(buildHiddenParamsSection(), gbc);

        // Row 3: Other Settings (full width - spans all 3 columns, takes remaining space)
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.gridx = 0; gbc.gridy = 3;
        gbc.gridwidth = 3;
        content.add(buildOtherSettingsSection(), gbc);

        JScrollPane scroll = new JScrollPane(content);
        scroll.setBorder(null);
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        scroll.setBackground(null);
        scroll.getViewport().setBackground(null);
        rootPanel.add(scroll, BorderLayout.CENTER);

        loadFromConfig();
        setupScanTypeRadios();
    }

    private JPanel buildToolbar() {
        JPanel toolbar = new JPanel(new BorderLayout());
        toolbar.setOpaque(true);
        toolbar.setBackground(UIManager.getColor("Panel.background"));
        if (toolbar.getBackground() == null) {
            toolbar.setBackground(new Color(240, 240, 245));
        }

        JPanel leftPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 6));
        leftPanel.setOpaque(false);

        JButton saveBtn = new JButton("Apply Settings");
        styleButton(saveBtn, new Color(40, 140, 80));
        saveBtn.addActionListener(e -> applySettings());
        leftPanel.add(saveBtn);

        JButton resetBtn = new JButton("Reset");
        styleButton(resetBtn, new Color(100, 100, 160));
        resetBtn.addActionListener(e -> resetDefaults());
        leftPanel.add(resetBtn);

        // GitHub button - styled consistently with other buttons
        JButton githubBtn = new JButton("GitHub");
        styleButton(githubBtn, new Color(0, 150, 136));
        githubBtn.addActionListener(e -> {
            try {
                java.awt.Desktop.getDesktop().browse(java.net.URI.create("https://github.com/VermaOps"));
            } catch (Exception ex) {
                if (statusArea != null) {
                    statusArea.setText("⚠️ Cannot open browser: " + ex.getMessage() + "\n\nPlease open https://github.com/VermaOps manually in your browser.\n\nCreator: VermaOps | GitHub");
                }
            }
        });
        leftPanel.add(githubBtn);

        // New Releases button - styled consistently with other buttons
        newReleasesBtn = new JButton("New Releases");
        styleButton(newReleasesBtn, new Color(155, 89, 182));
        newReleasesBtn.addActionListener(e -> handleNewReleasesClick());
        leftPanel.add(newReleasesBtn);

        JPanel rightPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 8, 6));
        rightPanel.setOpaque(false);

        cbProxyHistory = new JCheckBox("Proxy History");
        cbProxyHistory.setOpaque(false);
        cbProxyHistory.setFont(cbProxyHistory.getFont().deriveFont(11f));
        cbProxyHistory.setToolTipText("Capture requests from Proxy history");
        cbProxyHistory.setSelected(true);  // Default enabled

        cbScopeFilter = new JCheckBox("Scope Only");
        cbScopeFilter.setOpaque(false);
        cbScopeFilter.setFont(cbScopeFilter.getFont().deriveFont(11f));
        cbScopeFilter.setToolTipText("Respect Burp project scope settings");
        cbScopeFilter.setSelected(true);  // Default enabled

        cbRepeater = new JCheckBox("Repeater");
        cbRepeater.setOpaque(false);
        cbRepeater.setFont(cbRepeater.getFont().deriveFont(11f));
        cbRepeater.setToolTipText("Capture requests from Repeater");
        cbRepeater.setSelected(true);  // Default enabled

        rightPanel.add(cbProxyHistory);
        rightPanel.add(cbScopeFilter);
        rightPanel.add(cbRepeater);

        toolbar.add(leftPanel, BorderLayout.WEST);
        toolbar.add(rightPanel, BorderLayout.EAST);

        return toolbar;
    }

    private void styleButton(JButton btn, Color defaultBg) {
        btn.setFocusPainted(false);
        btn.setFont(btn.getFont().deriveFont(Font.BOLD, 11f));
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));

        Color bg = UIManager.getColor("Button.background");
        if (bg != null && isDarkTheme(bg)) {
            btn.setBackground(defaultBg.darker());
            btn.setForeground(Color.WHITE);
        } else if (bg != null) {
            btn.setBackground(defaultBg);
            btn.setForeground(Color.WHITE);
        } else {
            btn.setBackground(defaultBg);
            btn.setForeground(Color.WHITE);
        }
        btn.setBorderPainted(false);
        btn.setOpaque(true);
    }

    private boolean isDarkTheme(Color c) {
        double brightness = (c.getRed() * 0.299 + c.getGreen() * 0.587 + c.getBlue() * 0.114);
        return brightness < 128;
    }

    // ── Section builders ──────────────────────────────────────────────────

    private JPanel buildAIConfigurationSection() {
        JPanel p = createSectionPanel("AI Configuration");
        p.setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(3, 4, 3, 8);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 0;

        // Provider dropdown
        gbc.gridx = 0; gbc.gridy = 0;
        p.add(new JLabel("Provider:"), gbc);
        gbc.gridx = 1; gbc.gridwidth = 2;
        providerCombo = new JComboBox<>(new String[]{"Ollama", "OpenAI", "Claude"});
        providerCombo.setPreferredSize(new Dimension(150, 25));
        p.add(providerCombo, gbc);

        // Endpoint URL
        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 1;
        p.add(new JLabel("Endpoint:"), gbc);
        gbc.gridx = 1; gbc.gridwidth = 2;
        endpointField = new JTextField(config.getOllamaEndpoint(), 30);
        p.add(endpointField, gbc);

        // API Key
        gbc.gridx = 0; gbc.gridy = 2;
        p.add(new JLabel("API Key:"), gbc);
        gbc.gridx = 1; gbc.gridwidth = 2;
        apiKeyField = new JPasswordField(30);
        apiKeyField.setEnabled(false);
        p.add(apiKeyField, gbc);

        // Model
        gbc.gridx = 0; gbc.gridy = 3;
        p.add(new JLabel("Model:"), gbc);
        gbc.gridx = 1; gbc.gridwidth = 2;
        modelField = new JTextField(config.getOllamaModel(), 30);
        p.add(modelField, gbc);

        // Test Connection button and status
        gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 1;
        JButton testButton = new JButton("Test Connection");
        p.add(testButton, gbc);
        gbc.gridx = 1; gbc.gridwidth = 2;
        testStatusLabel = new JLabel(" ");
        testStatusLabel.setForeground(new Color(0, 150, 0));
        p.add(testStatusLabel, gbc);

        // Available Models list
        gbc.gridx = 0; gbc.gridy = 5; gbc.gridwidth = 3;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weightx = 1.0;
        gbc.weighty = 0.5;
        JPanel modelsPanel = new JPanel(new BorderLayout());
        modelsPanel.setBorder(BorderFactory.createTitledBorder("Available Models"));
        modelListModel = new DefaultListModel<>();
        JList<String> modelList = new JList<>(modelListModel);
        modelList.setVisibleRowCount(4);
        modelList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        modelList.addListSelectionListener(ev -> {
            if (!ev.getValueIsAdjusting()) {
                String selectedModel = modelList.getSelectedValue();
                if (selectedModel != null) {
                    modelField.setText(selectedModel);
                }
            }
        });
        JScrollPane modelScroll = new JScrollPane(modelList);
        modelsPanel.add(modelScroll, BorderLayout.CENTER);
        modelNoteLabel = new JLabel("Connect to see available models");
        modelNoteLabel.setFont(modelNoteLabel.getFont().deriveFont(Font.ITALIC, 11f));
        modelNoteLabel.setForeground(Color.GRAY);
        modelsPanel.add(modelNoteLabel, BorderLayout.SOUTH);
        p.add(modelsPanel, gbc);

        // Provider change listener
        providerCombo.addActionListener(e -> {
            String selected = (String) providerCombo.getSelectedItem();
            boolean isOllama = "Ollama".equals(selected);
            apiKeyField.setEnabled(!isOllama);
            modelListModel.clear();
            
            if (isOllama) {
                endpointField.setText(config.getOllamaEndpoint());
                modelField.setText(config.getOllamaModel());
                apiKeyField.setText("");
                modelNoteLabel.setText("Click 'Test Connection' to see available models");
                modelNoteLabel.setForeground(Color.GRAY);
            } else if ("OpenAI".equals(selected)) {
                endpointField.setText(config.getOpenAIBaseUrl());
                modelField.setText(config.getOpenAIModel());
                apiKeyField.setText(config.getOpenAIKey());
                modelNoteLabel.setText("Click 'Test Connection' to fetch available models");
                modelNoteLabel.setForeground(Color.GRAY);
            } else if ("Claude".equals(selected)) {
                endpointField.setText(config.getClaudeBaseUrl());
                modelField.setText(config.getClaudeModel());
                apiKeyField.setText(config.getClaudeKey());
                modelNoteLabel.setText("Click 'Test Connection' to see available models");
                modelNoteLabel.setForeground(Color.GRAY);
            }
        });

        testButton.addActionListener(e -> {
            String provider = (String) providerCombo.getSelectedItem();
            String endpoint = endpointField.getText().trim();
            String model = modelField.getText().trim();
            String apiKey = new String(apiKeyField.getPassword());

            testStatusLabel.setText("Testing...");
            testStatusLabel.setForeground(Color.BLACK);
            modelListModel.clear();
            modelNoteLabel.setText("Testing connection...");

            // Clear previous status
            if (statusArea != null) {
                statusArea.setText("");
            }

            SwingWorker<Boolean, Void> worker = new SwingWorker<>() {
                @Override
                protected Boolean doInBackground() {
                    try {
                        if ("Ollama".equals(provider)) {
                            OllamaProvider testProvider = new OllamaProvider(endpoint, model,
                                config.getAIConnectTimeout(), config.getAIReadTimeout(), config.getAIMaxTokens());
                            return testProvider.isAvailable();
                        } else if ("OpenAI".equals(provider)) {
                            OpenAIProvider testProvider = new OpenAIProvider(apiKey, model,
                                config.getAIConnectTimeout(), config.getAIReadTimeout(), config.getAIMaxTokens());
                            // Use custom base URL if changed from default
                            if (endpoint != null && !endpoint.isEmpty() && !endpoint.equals("https://api.openai.com")) {
                                testProvider = new OpenAIProvider(apiKey, endpoint, model,
                                    config.getAIConnectTimeout(), config.getAIReadTimeout(), config.getAIMaxTokens());
                            }
                            return testProvider.validateApiKey();
                        } else if ("Claude".equals(provider)) {
                            ClaudeProvider testProvider = new ClaudeProvider(apiKey, model,
                                config.getAIConnectTimeout(), config.getAIReadTimeout(), config.getAIMaxTokens());
                            // Use custom base URL if changed from default
                            if (endpoint != null && !endpoint.isEmpty() && !endpoint.equals("https://api.anthropic.com")) {
                                testProvider = new ClaudeProvider(apiKey, endpoint, model,
                                    config.getAIConnectTimeout(), config.getAIReadTimeout(), config.getAIMaxTokens());
                            }
                            return testProvider.validateApiKey();
                        }
                        return false;
                    } catch (Exception ex) {
                        return false;
                    }
                }

                @Override
                protected void done() {
                    try {
                        boolean connected = get();
                        if (connected) {
                            testStatusLabel.setText("✓ Connected");
                            testStatusLabel.setForeground(new Color(0, 150, 0));
                            modelNoteLabel.setText("✓ Connected successfully, fetching models...");
                            modelNoteLabel.setForeground(new Color(0, 100, 0));
                            modelListModel.clear();
                            
                            // Update Status panel based on provider
                            if (statusArea != null) {
                                if ("Ollama".equals(provider)) {
                                    statusArea.setText("Ollama is connected.\nModel: " + model + "\n\nCreator: VermaOps | GitHub");
                                } else {
                                    statusArea.setText(provider + " is connected.\nModel: " + model + "\n\nCreator: VermaOps | GitHub");
                                }
                            }

                            if ("Ollama".equals(provider)) {
                                fetchOllamaModels(endpoint);
                            } else if ("OpenAI".equals(provider)) {
                                fetchOpenAIModels(endpoint, apiKey);
                            } else if ("Claude".equals(provider)) {
                                fetchClaudeModels(endpoint, apiKey);
                            }
                        } else {
                            testStatusLabel.setText("✗ Failed");
                            testStatusLabel.setForeground(Color.RED);
                            modelNoteLabel.setText("Connection failed - Check API key and endpoint");
                            modelNoteLabel.setForeground(Color.RED);

                            // Update Status panel with failure message
                            if (statusArea != null) {
                                if ("Ollama".equals(provider)) {
                                    statusArea.setText("Ollama is not running. \nTry `ollama serve`.\n\nCreator: VermaOps | GitHub");
                                } else {
                                    statusArea.setText("Connection Unsuccessful.\nInvalid API key or URL. \nCheck your API key or URL and try again.\n\n🚨 Settings are not saved.\n\nCreator: VermaOps | GitHub");
                                }
                            }
                        }
                    } catch (Exception ex) {
                        testStatusLabel.setText("✗ Error: " + ex.getMessage());
                        testStatusLabel.setForeground(Color.RED);
                        modelNoteLabel.setText("Error: " + ex.getMessage());
                        modelNoteLabel.setForeground(Color.RED);

                        // Update Status panel with error
                        if (statusArea != null) {
                            if ("Ollama".equals(provider)) {
                                statusArea.setText("Ollama is not running. \nTry `ollama serve`.\n\nCreator: VermaOps | GitHub");
                            } else {
                                statusArea.setText("Connection Unsuccessful.\nInvalid API key or URL. \nCheck your API key or URL and try again.\n\n🚨 Settings are not saved.\n\nCreator: VermaOps | GitHub");
                            }
                        }
                    }
                }
            };
            worker.execute();
        });

        return p;
    }

    private void fetchOllamaModels(String endpoint) {
        final String endpointUrl = endpoint;
        SwingWorker<List<String>, Void> worker = new SwingWorker<>() {
            @Override
            protected List<String> doInBackground() {
                List<String> models = new ArrayList<>();
                try {
                    java.net.URL url = new java.net.URI(endpointUrl + "/api/tags").toURL();
                    java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
                    conn.setRequestMethod("GET");
                    conn.setConnectTimeout(5000);
                    conn.setReadTimeout(5000);

                    if (conn.getResponseCode() == 200) {
                        StringBuilder response = new StringBuilder();
                        try (java.io.BufferedReader br = new java.io.BufferedReader(
                                new java.io.InputStreamReader(conn.getInputStream(), java.nio.charset.StandardCharsets.UTF_8))) {
                            String line;
                            while ((line = br.readLine()) != null) {
                                response.append(line);
                            }
                        }
                        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("\"name\"\\s*:\\s*\"([^\"]+)\"");
                        java.util.regex.Matcher matcher = pattern.matcher(response.toString());
                        while (matcher.find()) {
                            models.add(matcher.group(1));
                        }
                    }
                    conn.disconnect();
                } catch (Exception e) {
                    // Silently fail
                }
                return models;
            }

            @Override
            protected void done() {
                try {
                    List<String> models = get();
                    if (!models.isEmpty()) {
                        for (String m : models) {
                            modelListModel.addElement(m);
                        }
                        modelNoteLabel.setText(models.size() + " model(s) available");
                        modelNoteLabel.setForeground(new Color(0, 100, 0));
                    } else {
                        modelNoteLabel.setText("No models found. Run 'ollama pull <model>'");
                        modelNoteLabel.setForeground(new Color(200, 100, 0));
                    }
                } catch (Exception e) {
                    modelNoteLabel.setText("Failed to fetch models: " + e.getMessage());
                }
            }
        };
        worker.execute();
    }

    private void fetchOpenAIModels(String endpoint, String apiKey) {
        SwingWorker<List<String>, Void> worker = new SwingWorker<>() {
            @Override
            protected List<String> doInBackground() {
                List<String> models = new ArrayList<>();
                try {
                    String urlEndpoint = endpoint + "/v1/models";
                    java.net.URL url = new java.net.URI(urlEndpoint).toURL();
                    java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
                    conn.setRequestMethod("GET");
                    conn.setRequestProperty("Authorization", "Bearer " + apiKey);
                    conn.setConnectTimeout(5000);
                    conn.setReadTimeout(5000);

                    if (conn.getResponseCode() == 200) {
                        StringBuilder response = new StringBuilder();
                        try (java.io.BufferedReader br = new java.io.BufferedReader(
                                new java.io.InputStreamReader(conn.getInputStream(), java.nio.charset.StandardCharsets.UTF_8))) {
                            String line;
                            while ((line = br.readLine()) != null) {
                                response.append(line);
                            }
                        }
                        // Parse JSON response to extract model IDs
                        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("\"id\"\\s*:\\s*\"([^\"]+)\"");
                        java.util.regex.Matcher matcher = pattern.matcher(response.toString());
                        while (matcher.find()) {
                            String modelId = matcher.group(1);
                            // Filter for GPT models only
                            if (modelId.contains("gpt")) {
                                models.add(modelId);
                            }
                        }
                    }
                    conn.disconnect();
                } catch (Exception e) {
                    // Silently fail - will show error in UI
                }
                return models;
            }

            @Override
            protected void done() {
                try {
                    List<String> models = get();
                    if (!models.isEmpty()) {
                        for (String m : models) {
                            modelListModel.addElement(m);
                        }
                        modelNoteLabel.setText(models.size() + " model(s) available from server");
                        modelNoteLabel.setForeground(new Color(0, 100, 0));
                    } else {
                        // Fallback to known models if fetch fails
                        String[] fallbackModels = {
                            "gpt-3.5-turbo", "gpt-3.5-turbo-16k", "gpt-4", 
                            "gpt-4-turbo-preview", "gpt-4o", "gpt-4o-mini"
                        };
                        for (String m : fallbackModels) {
                            modelListModel.addElement(m);
                        }
                        modelNoteLabel.setText("Could not fetch from server - showing common models");
                        modelNoteLabel.setForeground(new Color(200, 100, 0));
                    }
                } catch (Exception e) {
                    modelNoteLabel.setText("Failed to fetch models: " + e.getMessage());
                    modelNoteLabel.setForeground(Color.RED);
                }
            }
        };
        worker.execute();
    }

    private void fetchClaudeModels(String endpoint, String apiKey) {
        SwingWorker<List<String>, Void> worker = new SwingWorker<>() {
            @Override
            protected List<String> doInBackground() {
                List<String> models = new ArrayList<>();
                try {
                    String urlEndpoint = endpoint + "/v1/models";
                    java.net.URL url = new java.net.URI(urlEndpoint).toURL();
                    java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
                    conn.setRequestMethod("GET");
                    conn.setRequestProperty("x-api-key", apiKey);
                    conn.setRequestProperty("anthropic-version", "2023-06-01");
                    conn.setConnectTimeout(5000);
                    conn.setReadTimeout(5000);

                    if (conn.getResponseCode() == 200) {
                        StringBuilder response = new StringBuilder();
                        try (java.io.BufferedReader br = new java.io.BufferedReader(
                                new java.io.InputStreamReader(conn.getInputStream(), java.nio.charset.StandardCharsets.UTF_8))) {
                            String line;
                            while ((line = br.readLine()) != null) {
                                response.append(line);
                            }
                        }
                        // Parse JSON response to extract model IDs from data array
                        java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("\"id\"\\s*:\\s*\"([^\"]+)\"");
                        java.util.regex.Matcher matcher = pattern.matcher(response.toString());
                        while (matcher.find()) {
                            models.add(matcher.group(1));
                        }
                    }
                    conn.disconnect();
                } catch (Exception e) {
                    // Fallback to hardcoded models on error
                    models.add("claude-3-haiku-20240307");
                    models.add("claude-3-sonnet-20240229");
                    models.add("claude-3-opus-20240229");
                    models.add("claude-3-5-haiku-20241022");
                    models.add("claude-3-5-sonnet-20241022");
                }
                return models;
            }

            @Override
            protected void done() {
                try {
                    List<String> models = get();
                    modelListModel.clear();
                    if (!models.isEmpty()) {
                        for (String m : models) {
                            modelListModel.addElement(m);
                        }
                        modelNoteLabel.setText(models.size() + " model(s) available from server");
                        modelNoteLabel.setForeground(new Color(0, 100, 0));
                    } else {
                        modelNoteLabel.setText("No models found - check API key permissions");
                        modelNoteLabel.setForeground(new Color(200, 100, 0));
                    }
                } catch (Exception e) {
                    modelNoteLabel.setText("Failed to fetch models: " + e.getMessage());
                    modelNoteLabel.setForeground(Color.RED);
                }
            }
        };
        worker.execute();
    }

    private JPanel buildExclusionsSection() {
        JPanel p = createSectionPanel("Exclusions");
        p.setLayout(new GridLayout(2, 1, 8, 8));

        taExcludedParams = createTextArea(String.join("\n", config.getExcludedParams()), 4);
        taExcludedPaths = createTextArea(String.join("\n", config.getExcludedPaths()), 4);

        p.add(createLabeledScroll("Excluded Parameter Names:", taExcludedParams));
        p.add(createLabeledScroll("Excluded URL Paths:", taExcludedPaths));

        return p;
    }

    private JPanel buildStatusSection() {
        JPanel p = createSectionPanel("Status");
        p.setLayout(new BorderLayout());

        // Set maximum width to 250px to keep panel compact
        p.setMaximumSize(new java.awt.Dimension(250, Integer.MAX_VALUE));
        
        statusArea = new JTextArea();
        statusArea.setEditable(false);
        statusArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        statusArea.setBackground(UIManager.getColor("TextArea.background"));
        statusArea.setForeground(UIManager.getColor("TextArea.foreground"));
        statusArea.setLineWrap(true);           // enable line wrapping
        statusArea.setWrapStyleWord(true);      // wrap at word boundaries
        statusArea.setText(
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" +
            "     Welcome to SQLi Hunter      \n" +
            "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n" +
            "📋 Getting Started:\n" +
            "   • Start with default settings\n" +
            "   • Or customize your scan rules below\n\n" +
            "🎯 Quick Tips:\n" +
            "   • Right-click any request → Scan This Request\n" +
            "   • Monitor findings in the SQLi Runner tab\n" +
            "   • Raise confidence threshold to reduce FPs\n\n" +
            "⚙️ Active Configuration:\n" +
            "   • Choose your Scan Mode: Automated or Custom Only\n\n" +
            "👨‍💻 Creator: VermaOps | GitHub\n"
        );
        
        // Set columns to limit width (approximately 25-30 characters wide)
        statusArea.setColumns(25);

        JScrollPane scroll = new JScrollPane(statusArea);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        p.add(scroll, BorderLayout.CENTER);
        
        return p;
    }

    private JPanel buildScanTypeSection() {
        JPanel p = createSectionPanel("SCAN TYPE");
        p.setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 10, 5, 10);
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weightx = 1.0;  // Changed from 0.5 to 1.0 for better distribution
        gbc.weighty = 1;

        // Create a horizontal split panel for the two radio button sections
        JPanel topRowPanel = new JPanel(new GridLayout(1, 2, 20, 0));  // 1 row, 2 columns, 20px horizontal gap
        topRowPanel.setOpaque(false);
        
        // LEFT SIDE: Automated radio button with its description
        JPanel automatedRadioPanel = new JPanel(new BorderLayout());
        automatedRadioPanel.setOpaque(false);
        
        JPanel automatedRadioWithDesc = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        automatedRadioWithDesc.setOpaque(false);
        rbAutomated = new JRadioButton("AUTOMATED", true);
        rbAutomated.setOpaque(false);
        JLabel automatedDesc = new JLabel("(Use payload types below)");
        automatedDesc.setFont(automatedDesc.getFont().deriveFont(Font.ITALIC, 10f));
        automatedDesc.setForeground(Color.GRAY);
        automatedRadioWithDesc.add(rbAutomated);
        automatedRadioWithDesc.add(automatedDesc);
        
        automatedRadioPanel.add(automatedRadioWithDesc, BorderLayout.WEST);
        
        // RIGHT SIDE: Custom radio button with its description
        JPanel customRadioPanel = new JPanel(new BorderLayout());
        customRadioPanel.setOpaque(false);
        
        JPanel customRadioWithDesc = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        customRadioWithDesc.setOpaque(false);
        rbCustom = new JRadioButton("CUSTOM", false);
        rbCustom.setOpaque(false);
        JLabel customDesc = new JLabel("(Use only custom payloads)");
        customDesc.setFont(customDesc.getFont().deriveFont(Font.ITALIC, 10f));
        customDesc.setForeground(Color.GRAY);
        customRadioWithDesc.add(rbCustom);
        customRadioWithDesc.add(customDesc);
        
        customRadioPanel.add(customRadioWithDesc, BorderLayout.WEST);
        
        // Add both sides to the top row panel
        topRowPanel.add(automatedRadioPanel);
        topRowPanel.add(customRadioPanel);
        
        // Button group for mutual exclusivity
        ButtonGroup group = new ButtonGroup();
        group.add(rbAutomated);
        group.add(rbCustom);

        // Payload Types panel (LEFT column content)
        JPanel payloadTypesPanel = new JPanel();
        payloadTypesPanel.setLayout(new BoxLayout(payloadTypesPanel, BoxLayout.Y_AXIS));
        payloadTypesPanel.setOpaque(false);
        payloadTypesPanel.setBorder(BorderFactory.createTitledBorder("Payload Types"));

        cbError = createCheckBox("Error-Based", "Trigger database error messages to confirm injection");
        cbBoolean = createCheckBox("Boolean-Based", "Compare responses for conditional payloads");
        cbTime = createCheckBox("Time-Based", "Confirm blind injection via response timing");
        cbUnion = createCheckBox("Union-Based", "Attempt column-count enumeration and data leakage — noisier");

        payloadTypesPanel.add(cbError);
        payloadTypesPanel.add(cbBoolean);
        payloadTypesPanel.add(cbTime);
        payloadTypesPanel.add(cbUnion);
        payloadTypesPanel.add(Box.createVerticalGlue());  // Push content to top

        // Custom Payloads panel (RIGHT column content)
        JPanel customPayloadsPanel = new JPanel(new BorderLayout());
        customPayloadsPanel.setOpaque(false);
        customPayloadsPanel.setBorder(BorderFactory.createTitledBorder("Custom Payloads"));

        JLabel customInstr = new JLabel("One payload per line. Lines starting with # are ignored:");
        customInstr.setFont(customInstr.getFont().deriveFont(10f));
        customInstr.setForeground(Color.GRAY);
        customPayloadsPanel.add(customInstr, BorderLayout.NORTH);

        taCustomPayloads = createTextArea(config.getCustomPayloads(), 6);
        customPayloadsPanel.add(new JScrollPane(taCustomPayloads), BorderLayout.CENTER);

        // Create a wrapper panel for the two content columns
        JPanel contentPanel = new JPanel(new GridLayout(1, 2, 20, 0));  // 1 row, 2 columns
        contentPanel.setOpaque(false);
        contentPanel.add(payloadTypesPanel);
        contentPanel.add(customPayloadsPanel);
        
        // Layout: top row (radio buttons) then content panel below
        gbc.gridx = 0; gbc.gridy = 0; gbc.gridwidth = 1;
        gbc.weighty = 0;  // Don't expand vertically for top row
        p.add(topRowPanel, gbc);
        
        gbc.gridy = 1;
        gbc.weighty = 1;  // Allow content panel to expand
        p.add(contentPanel, gbc);

        return p;
    }

    private JPanel buildTargetAreasSection() {
        JPanel p = createSectionPanel("Target Areas");
        p.setLayout(new BorderLayout());
        
        // Top section: Target Areas (2-column grid)
        JPanel targetAreasPanel = new JPanel(new GridBagLayout());
        targetAreasPanel.setOpaque(false);
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(4, 8, 4, 8);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 0.5;
        gbc.gridwidth = 1;
        
        // Create checkboxes
        cbUrl = createCheckBox("URL Parameters", null);
        cbBody = createCheckBox("Body Parameters (form-encoded)", null);
        cbHeaders = createCheckBox("HTTP Headers", "⚠ Can be noisy — use carefully");
        cbCookies = createCheckBox("Cookies", null);
        cbJson = createCheckBox("JSON Body (including nested)", null);
        cbXml = createCheckBox("XML Body", null);
        cbHidden = createCheckBox("Test Hidden / Undiscovered Params", 
            "Appends common parameter names as URL params to discover undocumented inputs");
        
        // Row 1: URL Parameters | JSON Body
        gbc.gridx = 0; gbc.gridy = 0;
        targetAreasPanel.add(cbUrl, gbc);
        gbc.gridx = 1;
        targetAreasPanel.add(cbJson, gbc);
        
        // Row 2: Body Parameters | XML Body
        gbc.gridx = 0; gbc.gridy = 1;
        targetAreasPanel.add(cbBody, gbc);
        gbc.gridx = 1;
        targetAreasPanel.add(cbXml, gbc);
        
        // Row 3: HTTP Headers | Test Hidden Params
        gbc.gridx = 0; gbc.gridy = 2;
        targetAreasPanel.add(cbHeaders, gbc);
        gbc.gridx = 1;
        targetAreasPanel.add(cbHidden, gbc);
        
        // Row 4: Cookies (spanning both columns, left-aligned)
        gbc.gridx = 0; gbc.gridy = 3;
        gbc.gridwidth = 2;
        gbc.weightx = 1;
        JPanel cookieWrapper = new JPanel(new FlowLayout(FlowLayout.LEFT, 0, 0));
        cookieWrapper.setOpaque(false);
        cookieWrapper.add(cbCookies);
        targetAreasPanel.add(cookieWrapper, gbc);
        
        p.add(targetAreasPanel, BorderLayout.CENTER);
        
        // Bottom section: HTTP Methods
        JPanel httpMethodsPanel = new JPanel();
        httpMethodsPanel.setOpaque(false);
        httpMethodsPanel.setBorder(BorderFactory.createTitledBorder("HTTP Methods to Scan"));
        httpMethodsPanel.setLayout(new GridBagLayout());
        GridBagConstraints mgbc = new GridBagConstraints();
        mgbc.anchor = GridBagConstraints.WEST;
        mgbc.insets = new Insets(4, 12, 4, 12);
        mgbc.fill = GridBagConstraints.HORIZONTAL;
        
        // Create HTTP method checkboxes (existing ones)
        cbHttpGet = new JCheckBox("GET", true);
        cbHttpPost = new JCheckBox("POST", true);
        cbHttpPut = new JCheckBox("PUT", true);
        cbHttpPatch = new JCheckBox("PATCH", true);
        cbHttpDelete = new JCheckBox("DELETE", true);
        cbExcludeOptions = new JCheckBox("Exclude OPTIONS", false);
        
        // Style them consistently
        JCheckBox[] httpBoxes = {cbHttpGet, cbHttpPost, cbHttpPut, cbHttpPatch, cbHttpDelete, cbExcludeOptions};
        for (JCheckBox box : httpBoxes) {
            box.setOpaque(false);
            box.setFont(box.getFont().deriveFont(12f));
        }
        
        // Row 1: GET, POST, PUT
        mgbc.gridx = 0; mgbc.gridy = 0;
        httpMethodsPanel.add(cbHttpGet, mgbc);
        mgbc.gridx = 1;
        httpMethodsPanel.add(cbHttpPost, mgbc);
        mgbc.gridx = 2;
        httpMethodsPanel.add(cbHttpPut, mgbc);
        
        // Row 2: PATCH, DELETE, Exclude OPTIONS
        mgbc.gridx = 0; mgbc.gridy = 1;
        httpMethodsPanel.add(cbHttpPatch, mgbc);
        mgbc.gridx = 1;
        httpMethodsPanel.add(cbHttpDelete, mgbc);
        mgbc.gridx = 2;
        httpMethodsPanel.add(cbExcludeOptions, mgbc);
        
        p.add(httpMethodsPanel, BorderLayout.SOUTH);
        
        // Database Type selection
        JPanel dbTypePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 4));
        dbTypePanel.setOpaque(false);
        dbTypePanel.setBorder(BorderFactory.createTitledBorder("Database Type"));
        
        dbTypePanel.add(new JLabel("Target DBMS:"));
        dbTypeCombo = new JComboBox<>(new String[]{"Generic", "MySQL", "PostgreSQL", "MSSQL", "Oracle"});
        dbTypeCombo.setToolTipText("Select database type for targeted payloads (Generic works for most cases)");
        dbTypePanel.add(dbTypeCombo);
        
        httpMethodsPanel.add(dbTypePanel);

        return p;
    }

    private JPanel buildErrorSigsSection() {
        JPanel p = createSectionPanel("SQL Error Signatures");
        p.setLayout(new BorderLayout());

        JLabel instrLabel = new JLabel("Patterns matched case-insensitively against response body:");
        instrLabel.setForeground(UIManager.getColor("Label.foreground"));
        p.add(instrLabel, BorderLayout.NORTH);

        taErrorSigs = createTextArea(String.join("\n", config.getErrorSignatures()), 12);
        p.add(new JScrollPane(taErrorSigs), BorderLayout.CENTER);

        return p;
    }

    private JPanel buildHiddenParamsSection() {
        JPanel p = createSectionPanel("Hidden Parameters");
        p.setLayout(new BorderLayout());

        JLabel instrLabel = new JLabel("Parameter names to test for discovery (one per line):");
        instrLabel.setForeground(UIManager.getColor("Label.foreground"));
        p.add(instrLabel, BorderLayout.NORTH);

        taHiddenParams = createTextArea(String.join("\n", config.getHiddenParamNames()), 12);
        p.add(new JScrollPane(taHiddenParams), BorderLayout.CENTER);

        return p;
    }

    private JPanel buildOtherSettingsSection() {
        JPanel p = createSectionPanel("Other Settings");
        p.setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 10, 5, 10);
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weightx = 0.5;
        gbc.weighty = 1;

        // Rate Limiting panel
        JPanel rateLimitPanel = new JPanel(new GridBagLayout());
        rateLimitPanel.setOpaque(false);
        rateLimitPanel.setBorder(BorderFactory.createTitledBorder("Rate Limiting & Impact Reduction"));
        GridBagConstraints rlGbc = new GridBagConstraints();
        rlGbc.anchor = GridBagConstraints.WEST;
        rlGbc.insets = new Insets(3, 4, 3, 8);

        spDelay = createSpinner(0, 0, 10000, 50);
        spTimeout = createSpinner(10000, 1000, 60000, 1000);
        //spThreads = createSpinner(3, 1, 10, 1);

        addSettingRow(rateLimitPanel, rlGbc, 0, "Request Delay (ms):", spDelay, "Pause between each payload request to reduce target impact");
        addSettingRow(rateLimitPanel, rlGbc, 1, "Request Timeout (ms):", spTimeout, null);
        //addSettingRow(rateLimitPanel, rlGbc, 3, "Thread Pool Size:", spThreads, null);

        // Detection Thresholds panel
        JPanel detectionPanel = new JPanel(new GridBagLayout());
        detectionPanel.setOpaque(false);
        detectionPanel.setBorder(BorderFactory.createTitledBorder("Detection Thresholds"));
        GridBagConstraints dtGbc = new GridBagConstraints();
        dtGbc.anchor = GridBagConstraints.WEST;
        dtGbc.insets = new Insets(3, 4, 3, 8);

        spConfidence = createSpinner(0, 0, 100, 5);
        spTimingMult = createDoubleSpinner(0, 0, 20.0, 0.1);
        spSleepSec = createSpinner(6, 3, 30, 1);

        addSettingRow(detectionPanel, dtGbc, 0, "Min Confidence Score (0-100):", spConfidence, "Findings below this score are suppressed — lower = more results, more false positives");
        addSettingRow(detectionPanel, dtGbc, 1, "Timing Ratio Threshold (×baseline):", spTimingMult, "Response must be at least this many times the baseline to flag as time-based");
        addSettingRow(detectionPanel, dtGbc, 2, "Time-Based Sleep Duration (seconds):", spSleepSec, "How long SLEEP/WAITFOR payloads will pause the DB");

        gbc.gridx = 0; gbc.gridy = 0;
        p.add(rateLimitPanel, gbc);
        gbc.gridx = 1;
        p.add(detectionPanel, gbc);

        return p;
    }

    // ── Helper methods ────────────────────────────────────────────────────

    private JPanel createSectionPanel(String title) {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        p.setOpaque(false);
        p.setMaximumSize(new Dimension(Integer.MAX_VALUE, Integer.MAX_VALUE));

        Border lineBorder = BorderFactory.createLineBorder(
            UIManager.getColor("Separator.foreground") != null
                ? UIManager.getColor("Separator.foreground")
                : new Color(180, 180, 200),
            1
        );
        TitledBorder border = BorderFactory.createTitledBorder(lineBorder, " " + title + " ");
        border.setTitleFont(border.getTitleFont().deriveFont(Font.BOLD));

        Color titleColor = UIManager.getColor("Label.foreground");
        if (titleColor == null) {
            titleColor = new Color(40, 40, 120);
        }
        border.setTitleColor(titleColor);
        p.setBorder(border);

        return p;
    }

    private JCheckBox createCheckBox(String label, String tooltip) {
        JCheckBox cb = new JCheckBox(label);
        cb.setOpaque(false);
        cb.setFont(cb.getFont().deriveFont(12f));
        if (tooltip != null) cb.setToolTipText(tooltip);
        return cb;
    }

    private JSpinner createSpinner(int val, int min, int max, int step) {
        JSpinner s = new JSpinner(new SpinnerNumberModel(val, min, max, step));
        s.setPreferredSize(new Dimension(90, 24));
        return s;
    }

    private JSpinner createDoubleSpinner(double val, double min, double max, double step) {
        JSpinner s = new JSpinner(new SpinnerNumberModel(val, min, max, step));
        s.setPreferredSize(new Dimension(90, 24));
        return s;
    }

    private JTextArea createTextArea(String content, int rows) {
        JTextArea ta = new JTextArea(content, rows, 30);
        ta.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 11));
        ta.setLineWrap(true);
        ta.setWrapStyleWord(false);
        ta.setBackground(UIManager.getColor("TextArea.background"));
        ta.setForeground(UIManager.getColor("TextArea.foreground"));
        ta.setCaretColor(UIManager.getColor("TextArea.foreground"));
        return ta;
    }

    private JPanel createLabeledScroll(String label, JTextArea ta) {
        JPanel p = new JPanel(new BorderLayout(0, 2));
        p.setOpaque(false);

        JLabel lbl = new JLabel(label);
        lbl.setForeground(UIManager.getColor("Label.foreground"));
        p.add(lbl, BorderLayout.NORTH);

        JScrollPane scroll = new JScrollPane(ta);
        scroll.getViewport().setBackground(UIManager.getColor("TextArea.background"));
        p.add(scroll, BorderLayout.CENTER);
        return p;
    }

    private void addSettingRow(JPanel panel, GridBagConstraints gbc, int row, String label, JComponent comp, String tooltip) {
        gbc.gridx = 0; gbc.gridy = row; gbc.weightx = 0;

        JLabel lbl = new JLabel(label);
        lbl.setFont(lbl.getFont().deriveFont(12f));
        lbl.setForeground(UIManager.getColor("Label.foreground"));
        if (tooltip != null) {
            lbl.setToolTipText(tooltip);
            comp.setToolTipText(tooltip);
        }
        panel.add(lbl, gbc);

        gbc.gridx = 1; gbc.weightx = 1;
        panel.add(comp, gbc);
    }

    private void setupScanTypeRadios() {
        rbAutomated.addActionListener(e -> {
            boolean isAutomated = rbAutomated.isSelected();
            cbError.setEnabled(isAutomated);
            cbBoolean.setEnabled(isAutomated);
            cbTime.setEnabled(isAutomated);
            cbUnion.setEnabled(isAutomated);
            taCustomPayloads.setEnabled(!isAutomated);
            dbTypeCombo.setEnabled(isAutomated);  // Enable DB type dropdown for Automated
            config.setUseCustomOnly(!isAutomated);
        });

        rbCustom.addActionListener(e -> {
            boolean isCustom = rbCustom.isSelected();
            cbError.setEnabled(!isCustom);
            cbBoolean.setEnabled(!isCustom);
            cbTime.setEnabled(!isCustom);
            cbUnion.setEnabled(!isCustom);
            taCustomPayloads.setEnabled(isCustom);
            dbTypeCombo.setEnabled(!isCustom);  // Disable DB type dropdown for Custom
            config.setUseCustomOnly(isCustom);
        });
    }

    // ── Load / Apply / Reset ──────────────────────────────────────────────

    private void loadFromConfig() {
        // Load scan mode
        boolean useCustomOnly = config.isUseCustomOnly();
        if (useCustomOnly) {
            rbCustom.setSelected(true);
        } else {
            rbAutomated.setSelected(true);
        }
        setupScanTypeRadios();
        // Set initial DB type dropdown enabled state based on scan mode
        dbTypeCombo.setEnabled(!useCustomOnly);

        // Payload types
        cbError.setSelected(config.isEnableErrorBased());
        cbBoolean.setSelected(config.isEnableBooleanBased());
        cbTime.setSelected(config.isEnableTimeBased());
        cbUnion.setSelected(config.isEnableUnionBased());

        // Target areas
        cbUrl.setSelected(config.isScanUrlParams());
        cbBody.setSelected(config.isScanBodyParams());
        cbJson.setSelected(config.isScanJsonBody());
        cbXml.setSelected(config.isScanXmlBody());
        cbHeaders.setSelected(config.isScanHeaders());
        cbCookies.setSelected(config.isScanCookies());
        cbHidden.setSelected(config.isTestHiddenParams());

        // Rate limiting
        spDelay.setValue(config.getRequestDelayMs());
        spTimeout.setValue(config.getTimeoutMs());
        //spThreads.setValue(config.getThreadPoolSize());

        // Detection
        spConfidence.setValue(config.getMinConfidenceScore());
        spTimingMult.setValue(config.getTimingMultiplier());
        spSleepSec.setValue(config.getTimingBaselineSleepSec());

        // Text areas
        taExcludedParams.setText(String.join("\n", config.getExcludedParams()));
        taExcludedPaths.setText(String.join("\n", config.getExcludedPaths()));
        taCustomPayloads.setText(config.getCustomPayloads());
        taErrorSigs.setText(String.join("\n", config.getErrorSignatures()));
        taHiddenParams.setText(String.join("\n", config.getHiddenParamNames()));

        // AI settings (from ScanConfig - these will be loaded by the UI directly)
        // The AI section fields are populated based on provider combo selection
        String activeProvider = config.getActiveAIProvider();
        if ("ollama".equals(activeProvider)) {
            providerCombo.setSelectedItem("Ollama");
            endpointField.setText(config.getOllamaEndpoint());
            modelField.setText(config.getOllamaModel());
        } else if ("openai".equals(activeProvider)) {
            providerCombo.setSelectedItem("OpenAI");
            endpointField.setText(config.getOpenAIBaseUrl());
            modelField.setText(config.getOpenAIModel());
            apiKeyField.setText(config.getOpenAIKey());
        } else if ("claude".equals(activeProvider)) {
            providerCombo.setSelectedItem("Claude");
            endpointField.setText(config.getClaudeBaseUrl());
            modelField.setText(config.getClaudeModel());
            apiKeyField.setText(config.getClaudeKey());
        }

        // Load HTTP Method Filtering settings
        cbHttpGet.setSelected(config.isMethodGetEnabled());
        cbHttpPost.setSelected(config.isMethodPostEnabled());
        cbHttpPut.setSelected(config.isMethodPutEnabled());
        cbHttpPatch.setSelected(config.isMethodPatchEnabled());
        cbHttpDelete.setSelected(config.isMethodDeleteEnabled());
        cbExcludeOptions.setSelected(config.isExcludeOptions());

        // Load Database Type setting
        String dbType = config.getSelectedDatabaseType();
        switch (dbType) {
            case "MySQL": dbTypeCombo.setSelectedIndex(1); break;
            case "PostgreSQL": dbTypeCombo.setSelectedIndex(2); break;
            case "MSSQL": dbTypeCombo.setSelectedIndex(3); break;
            case "Oracle": dbTypeCombo.setSelectedIndex(4); break;
            default: dbTypeCombo.setSelectedIndex(0); break;
        }

        // Load Traffic Source Filter settings
        cbProxyHistory.setSelected(config.isProxyHistoryEnabled());
        cbScopeFilter.setSelected(config.isScopeFilterEnabled());
        cbRepeater.setSelected(config.isRepeaterEnabled());
    }

    private void applySettings() {
        // ── API Key Validation for non-Ollama providers ─────────────────────
        String selectedProvider = (String) providerCombo.getSelectedItem();
        boolean isOllama = "Ollama".equals(selectedProvider);
        
        if (!isOllama) {
            String apiKey = new String(apiKeyField.getPassword());
            if (apiKey == null || apiKey.trim().isEmpty()) {
                if (statusArea != null) {
                    statusArea.setText("Invalid API key. Check your key or switch to Ollama with a valid model name.\n\n🚨 Settings are not saved.\n\nCreator: VermaOps | GitHub");
                }
                return;
            }
            
            // Validate the API key actually works
            String endpoint = endpointField.getText().trim();
            String model = modelField.getText().trim();
            boolean keyValid = false;
            
            try {
                if ("OpenAI".equals(selectedProvider)) {
                    OpenAIProvider testProvider = new OpenAIProvider(apiKey, model,
                        config.getAIConnectTimeout(), config.getAIReadTimeout(), config.getAIMaxTokens());
                    if (endpoint != null && !endpoint.isEmpty() && !endpoint.equals("https://api.openai.com")) {
                        testProvider = new OpenAIProvider(apiKey, endpoint, model,
                            config.getAIConnectTimeout(), config.getAIReadTimeout(), config.getAIMaxTokens());
                    }
                    keyValid = testProvider.validateApiKey();
                } else if ("Claude".equals(selectedProvider)) {
                    ClaudeProvider testProvider = new ClaudeProvider(apiKey, model,
                        config.getAIConnectTimeout(), config.getAIReadTimeout(), config.getAIMaxTokens());
                    if (endpoint != null && !endpoint.isEmpty() && !endpoint.equals("https://api.anthropic.com")) {
                        testProvider = new ClaudeProvider(apiKey, endpoint, model,
                            config.getAIConnectTimeout(), config.getAIReadTimeout(), config.getAIMaxTokens());
                    }
                    keyValid = testProvider.validateApiKey();
                }
            } catch (Exception e) {
                keyValid = false;
            }
            
            if (!keyValid) {
                if (statusArea != null) {
                    statusArea.setText("Invalid API key. Check your key or switch to Ollama with a valid model name.\n\n🚨 Settings are not saved.\n\nCreator: VermaOps | GitHub");
                }
                return;
            }
        }
        
        // Scan mode
        config.setUseCustomOnly(rbCustom.isSelected());

        // Payload types
        config.setEnableErrorBased(cbError.isSelected());
        config.setEnableBooleanBased(cbBoolean.isSelected());
        config.setEnableTimeBased(cbTime.isSelected());
        config.setEnableUnionBased(cbUnion.isSelected());

        // Target areas
        config.setScanUrlParams(cbUrl.isSelected());
        config.setScanBodyParams(cbBody.isSelected());
        config.setScanJsonBody(cbJson.isSelected());
        config.setScanXmlBody(cbXml.isSelected());
        config.setScanHeaders(cbHeaders.isSelected());
        config.setScanCookies(cbCookies.isSelected());
        config.setTestHiddenParams(cbHidden.isSelected());

        // Rate limiting
        config.setRequestDelayMs((int) spDelay.getValue());
        config.setTimeoutMs((int) spTimeout.getValue());
        //config.setThreadPoolSize((int) spThreads.getValue());

        // Detection
        config.setMinConfidenceScore((int) spConfidence.getValue());
        config.setTimingMultiplier(((Number) spTimingMult.getValue()).doubleValue());
        config.setTimingBaselineSleepSec((int) spSleepSec.getValue());

        // Exclusions
        updateListFromTextArea(config.getExcludedParams(), taExcludedParams.getText());
        updateListFromTextArea(config.getExcludedPaths(), taExcludedPaths.getText());
        updateListFromTextArea(config.getErrorSignatures(), taErrorSigs.getText());
        updateListFromTextArea(config.getHiddenParamNames(), taHiddenParams.getText());
        config.setCustomPayloads(taCustomPayloads.getText());

        // AI Settings
        if ("Ollama".equals(selectedProvider)) {
            config.setActiveAIProvider("ollama");
            config.setOllamaEndpoint(endpointField.getText().trim());
            config.setOllamaModel(modelField.getText().trim());
        } else if ("OpenAI".equals(selectedProvider)) {
            config.setActiveAIProvider("openai");
            config.setOpenAIBaseUrl(endpointField.getText().trim());
            config.setOpenAIModel(modelField.getText().trim());
            config.setOpenAIKey(new String(apiKeyField.getPassword()));
        } else if ("Claude".equals(selectedProvider)) {
            config.setActiveAIProvider("claude");
            config.setClaudeBaseUrl(endpointField.getText().trim());
            config.setClaudeModel(modelField.getText().trim());
            config.setClaudeKey(new String(apiKeyField.getPassword()));
        }

        // Validate at least one traffic source is enabled
        if (!cbProxyHistory.isSelected() && !cbRepeater.isSelected()) {
            JOptionPane.showMessageDialog(rootPanel,
                    "Unable to save settings. Enable Proxy History or Repeater.",
                    "SQLi Hunter", JOptionPane.ERROR_MESSAGE);
            return;
        }

        // Save Traffic Source Filter settings
        config.setProxyHistoryEnabled(cbProxyHistory.isSelected());
        config.setScopeFilterEnabled(cbScopeFilter.isSelected());
        config.setRepeaterEnabled(cbRepeater.isSelected());

        // Save HTTP Method Filtering settings
        config.setMethodGetEnabled(cbHttpGet.isSelected());
        config.setMethodPostEnabled(cbHttpPost.isSelected());
        config.setMethodPutEnabled(cbHttpPut.isSelected());
        config.setMethodPatchEnabled(cbHttpPatch.isSelected());
        config.setMethodDeleteEnabled(cbHttpDelete.isSelected());
        config.setExcludeOptions(cbExcludeOptions.isSelected());

       // Save Database Type setting
        String selectedDb = (String) dbTypeCombo.getSelectedItem();
        config.setSelectedDatabaseType(selectedDb);

        // Update Status panel with success summary
        if (statusArea != null) {
            StringBuilder summary = new StringBuilder();
            summary.append("Settings updated successfully.\n\n");
            summary.append("AI provider: ").append(selectedProvider).append("\n\n");
            summary.append("Model: ").append(modelField.getText().trim()).append("\n\n");
            
            boolean isCustomMode = rbCustom.isSelected();
            summary.append("Scan type: ").append(isCustomMode ? "Custom" : "Automated").append("\n\n");
            
            if (isCustomMode) {
                summary.append("Database type: Custom Scan (user-defined payloads only)\n\n");
            } else {
                summary.append("Database type: ").append(selectedDb).append("\n\n");
            }
            
            summary.append("Exclusions are set.\n\n");
            summary.append("Target areas are set.\n\n");
            summary.append("SQL signatures are set.\n\n");
            summary.append("Hidden parameters are set.\n\n");
            summary.append("\nCreator: VermaOps | GitHub");
            statusArea.setText(summary.toString());
        }

        JOptionPane.showMessageDialog(rootPanel, "Settings applied successfully.",
                "SQLi Hunter", JOptionPane.INFORMATION_MESSAGE);

        if (onSettingsApplied != null) {
            onSettingsApplied.run();
        }

        // Notify ResultsPanel that AI provider settings may have changed
        if (onAIProviderChanged != null) {
            onAIProviderChanged.run();
        }
    }

    private void resetDefaults() {
        int confirm = JOptionPane.showConfirmDialog(rootPanel,
                "Reset all settings to defaults?", "Confirm Reset", JOptionPane.YES_NO_OPTION);
        if (confirm != JOptionPane.YES_OPTION) return;

        ScanConfig fresh = new ScanConfig();
        config.setUseCustomOnly(fresh.isUseCustomOnly());
        config.setEnableErrorBased(fresh.isEnableErrorBased());
        config.setEnableBooleanBased(fresh.isEnableBooleanBased());
        config.setEnableTimeBased(fresh.isEnableTimeBased());
        config.setEnableUnionBased(fresh.isEnableUnionBased());
        config.setScanUrlParams(fresh.isScanUrlParams());
        config.setScanBodyParams(fresh.isScanBodyParams());
        config.setScanJsonBody(fresh.isScanJsonBody());
        config.setScanXmlBody(fresh.isScanXmlBody());
        config.setScanHeaders(fresh.isScanHeaders());
        config.setScanCookies(fresh.isScanCookies());
        config.setTestHiddenParams(fresh.isTestHiddenParams());
        config.setRequestDelayMs(fresh.getRequestDelayMs());
        config.setTimeoutMs(fresh.getTimeoutMs());
        //config.setThreadPoolSize(fresh.getThreadPoolSize());
        config.setMinConfidenceScore(fresh.getMinConfidenceScore());
        config.setTimingMultiplier(fresh.getTimingMultiplier());
        config.setTimingBaselineSleepSec(fresh.getTimingBaselineSleepSec());
        config.setCustomPayloads("");
        config.setActiveAIProvider("ollama");
        config.setOllamaEndpoint("http://localhost:11434");
        config.setOllamaModel("llama2");
        config.setOpenAIKey("");
        config.setOpenAIBaseUrl("https://api.openai.com");
        config.setOpenAIModel("gpt-3.5-turbo");
        config.setClaudeKey("");
        config.setClaudeBaseUrl("https://api.anthropic.com");
        config.setClaudeModel("claude-3-haiku-20240307");

        // Reset HTTP Method Filtering settings to defaults
        config.setMethodGetEnabled(true);
        config.setMethodPostEnabled(true);
        config.setMethodPutEnabled(true);
        config.setMethodPatchEnabled(true);
        config.setMethodDeleteEnabled(true);
        config.setExcludeOptions(true);

        // Reset Traffic Source Filter settings to defaults
        config.setProxyHistoryEnabled(true);
        config.setScopeFilterEnabled(true);
        config.setRepeaterEnabled(true);
        config.getHiddenParamNames().clear();
        config.getHiddenParamNames().addAll(Arrays.asList(
            "desc", "order", "sort", "sortBy", "column", "field"
        ));

        loadFromConfig();

        // Update Status panel
        if (statusArea != null) {
            statusArea.setText("Default settings have been restored.\n\nCreator: VermaOps | GitHub");
        }
    }

    private void updateListFromTextArea(java.util.List<String> list, String text) {
        list.clear();
        for (String line : text.split("\n")) {
            String t = line.trim();
            if (!t.isEmpty() && !t.startsWith("#")) list.add(t);
        }
    }
    
    // ── Version Check Methods ─────────────────────────────────────────────

    private void handleNewReleasesClick() {
        if (statusArea != null) {
            statusArea.setText("System Status Information\n\n" +
                "• Checking for new version on GitHub...\n" +
                "• Please wait...\n\nCreator: VermaOps | GitHub");
        }
        
        SwingWorker<VersionCheckResult, Void> worker = new SwingWorker<>() {
            @Override
            protected VersionCheckResult doInBackground() {
                return checkForNewVersion();
            }
            
            @Override
            protected void done() {
                try {
                    VersionCheckResult result = get();
                    
                    if (result.error != null) {
                        if (statusArea != null) {
                            statusArea.setText("System Status Information\n\n" +
                                "• Version Check: FAILED\n" +
                                "• Error: " + result.error + "\n\nCreator: VermaOps | GitHub");
                        }
                        return;
                    }
                    
                    config.setLatestVersion(result.latestVersion);
                    config.setLastVersionCheckTime(System.currentTimeMillis());
                    config.setUpdateAvailable(result.updateAvailable);
                    
                    updateButtonColor(result.updateAvailable);
                    
                    if (result.updateAvailable && statusArea != null) {
                        statusArea.setText("System Status Information\n\n" +
                            "• New version available: " + result.latestVersion + "\n" +
                            "• Opening GitHub releases page...\n\nCreator: VermaOps | GitHub");
                        openGitHubReleasesPage();
                    } else if (statusArea != null) {
                        statusArea.setText("System Status Information\n\n" +
                            "• No new releases found.\n" +
                            "• Current version: " + VersionManager.getCurrentVersion() + "\n" +
                            "• Latest on GitHub: " + result.latestVersion + "\n\nCreator: VermaOps | GitHub");
                    }
                    
                } catch (Exception e) {
                    if (statusArea != null) {
                        statusArea.setText("System Status Information\n\n" +
                            "• Version Check: FAILED\n" +
                            "• Error: " + e.getMessage() + "\n\nCreator: VermaOps | GitHub");
                    }
                }
            }
        };
        worker.execute();
    }
    
    private void openGitHubReleasesPage() {
        try {
            java.awt.Desktop.getDesktop().browse(
                new java.net.URI(SQLiHunterExtension.GITHUB_RELEASES_URL));
        } catch (Exception ex) {
            if (statusArea != null) {
                statusArea.setText("System Status Information\n\n" +
                    "• Could not open browser: " + ex.getMessage() + "\n\nCreator: VermaOps | GitHub");
            }
        }
    }
    
    private void updateButtonColor(boolean updateAvailable) {
        SwingUtilities.invokeLater(() -> {
            if (newReleasesBtn != null) {
                if (updateAvailable) {
                    newReleasesBtn.setBackground(new Color(255, 200, 0));
                    newReleasesBtn.setOpaque(true);
                } else {
                    newReleasesBtn.setBackground(new Color(155, 89, 182));
                    newReleasesBtn.setOpaque(true);
                }
            }
        });
    }
    
    private VersionCheckResult checkForNewVersion() {
        String currentVersion = VersionManager.getCurrentVersion();
        
        try {
            java.net.URL url = new java.net.URI(SQLiHunterExtension.GITHUB_API_REPO + "/releases/latest").toURL();
            java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);
            conn.setRequestProperty("Accept", "application/vnd.github.v3+json");
            
            int responseCode = conn.getResponseCode();
            
            if (responseCode == 200) {
                StringBuilder response = new StringBuilder();
                try (java.io.BufferedReader br = new java.io.BufferedReader(
                        new java.io.InputStreamReader(conn.getInputStream()))) {
                    String line;
                    while ((line = br.readLine()) != null) {
                        response.append(line);
                    }
                }
                
                String tagName = VersionManager.extractTagName(response.toString());
                
                if (tagName != null) {
                    String latestVersion = tagName.startsWith("v") ? tagName.substring(1) : tagName;
                    boolean updateAvailable = VersionManager.compareVersions(latestVersion, currentVersion) > 0;
                    return new VersionCheckResult(latestVersion, updateAvailable, null);
                }
                return new VersionCheckResult(null, false, "Could not parse version from GitHub");
                
            } else if (responseCode == 403) {
                return new VersionCheckResult(null, false, "GitHub API rate limit exceeded");
            } else {
                return new VersionCheckResult(null, false, "GitHub error: " + responseCode);
            }
            
        } catch (java.net.UnknownHostException e) {
            return new VersionCheckResult(null, false, "No internet connection");
        } catch (java.net.SocketTimeoutException e) {
            return new VersionCheckResult(null, false, "Connection timeout");
        } catch (Exception e) {
            return new VersionCheckResult(null, false, "Check failed: " + e.getMessage());
        }
    }
    
    private static class VersionCheckResult {
        String latestVersion;
        boolean updateAvailable;
        String error;
        
        VersionCheckResult(String latestVersion, boolean updateAvailable, String error) {
            this.latestVersion = latestVersion;
            this.updateAvailable = updateAvailable;
            this.error = error;
        }
    }
}