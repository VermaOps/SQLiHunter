package main;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import javax.swing.border.*;
import javax.swing.table.*;
import java.awt.*;
import java.awt.datatransfer.StringSelection;
import java.util.List;
import java.util.Map;
import ai.ConversationHistory;
import ai.AIProvider;
import ai.AIResponse;
import ai.OllamaProvider;
import ai.OllamaProvider;
import ai.OpenAIProvider;
import ai.ClaudeProvider;

import burp.api.montoya.core.ByteArray;

/**
 * The "Findings" tab inside the SQLi Hunter suite tab.
 * Shows a sortable table of findings with details on selection.
 */
public class ResultsPanel {

    private final ResultsModel model;
    private final MontoyaApi api;
    private final ScanConfig scanConfig;
    private final ScanEngine scanEngine;

    // ── Table ────────────────────────────────────────────────────────────
    private final String[] COLUMNS = {
            "#",           // index 0
            "Type",        // index 1 - Error-Based/Boolean-Based/Time-Based/Union-Based/Custom
            "Parameter",   // index 2
            "Payload",     // index 3
            "Status",      // index 4 - HTTP status code
            "Time",        // index 5 - Response time in ms
            "Confidence",  // index 6 - Integer + "%"
            "Severity",    // index 7 - 🔴 High / 🟡 Medium / 🟢 Low / ⚪ Info
            "Location"     // index 8 - URL/Body/JSON/XML/Header/Cookie/Hidden
    };
    private final FindingsTableModel tableModel;
    private final JTable table;

    // ── Detail area ───────────────────────────────────────────────────────
    private final JTextArea evidenceArea;
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;

    private JPanel rootPanel;

    // AI Panel components
    private JTextArea aiPromptArea;
    private JTextArea aiResponseArea;
    private JButton aiSendButton;
    private JButton aiCancelButton;
    private JButton aiClearButton;
    private ConversationHistory currentConversation;
    private AIProvider aiProvider;
    private SwingWorker<String, Void> currentAIWorker;
    private volatile boolean aiRequestCancelled;
    private long cancelStartTime;
    
    // Scan status indicator
    private JLabel scanStatusLabel;

    private JScrollPane aiResponseScrollPane;  // Store reference for auto-scroll

    // Auto-scrolling
    private JScrollPane findingsTableScrollPane;
    private boolean autoScrollEnabled = true;

    public ResultsPanel(ResultsModel model, MontoyaApi api, ScanConfig scanConfig, ScanEngine scanEngine) {
        this.model = model;
        this.api = api;
        this.scanConfig = scanConfig;
        this.scanEngine = scanEngine;

        tableModel = new FindingsTableModel(COLUMNS);
        table = buildTable();
        evidenceArea = new JTextArea();
        // Create Burp's native editors which automatically adapt to theme
        this.requestEditor = api.userInterface().createHttpRequestEditor();
        this.responseEditor = api.userInterface().createHttpResponseEditor();

        // Initialize AI provider from scanConfig
        this.aiProvider = createAIProviderFromScanConfig();
        this.currentConversation = new ConversationHistory();

        buildUI();

        // Register model listener
        model.addListener(new ResultsModel.Listener() {
            @Override
            public void onFindingAdded(ScanFinding f) {
                SwingUtilities.invokeLater(() -> {
                    tableModel.addFinding(f);
                    if (autoScrollEnabled && findingsTableScrollPane != null) {
                        JScrollBar verticalBar = findingsTableScrollPane.getVerticalScrollBar();
                        if (verticalBar != null) {
                            verticalBar.setValue(verticalBar.getMaximum());
                        }
                    }
                });
            }
            @Override
            public void onCleared() {
                SwingUtilities.invokeLater(() -> {
                    tableModel.clear();
                    clearDetails();
                    autoScrollEnabled = true;
                });
            }
            @Override
            public void onFilterChanged() {
                SwingUtilities.invokeLater(() -> {
                    tableModel.rebuildRows();
                    clearDetails();
                    autoScrollEnabled = true;
                    if (findingsTableScrollPane != null) {
                        JScrollBar verticalBar = findingsTableScrollPane.getVerticalScrollBar();
                        if (verticalBar != null) {
                            verticalBar.setValue(0);
                        }
                    }
                });
            }
        });
    }

    public JPanel getPanel() { return rootPanel; }

    // ── UI construction ───────────────────────────────────────────────────

    private void buildUI() {
        rootPanel = new JPanel(new BorderLayout(0, 0));
        rootPanel.setBackground(Color.WHITE);

        // ── Toolbar ───────────────────────────────────────────────────────
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 6));
        toolbar.setBackground(new Color(30, 30, 50));

        JButton clearBtn = makeToolButton("Clear", new Color(180, 60, 60));
        clearBtn.addActionListener(e -> {
            int confirm = JOptionPane.showConfirmDialog(rootPanel,
                    "Clear all findings?", "Confirm", JOptionPane.YES_NO_OPTION);
            if (confirm == JOptionPane.YES_OPTION) model.clear();
        });
        toolbar.add(clearBtn);

        // Kill Switch button - same style as Clear button
        JButton killSwitchBtn = makeToolButton("Kill Switch OFF", new Color(180, 60, 60));
        killSwitchBtn.addActionListener(e -> {
            boolean currentState = scanConfig.isKillSwitchEnabled();
            if (!currentState) {
                // Switching ON - kill all running scans
                scanConfig.setKillSwitchEnabled(true);
                killSwitchBtn.setText("Kill Switch ON");
                if (scanEngine != null) {
                    scanEngine.cancelScan();
                }
            } else {
                // Switching OFF - allow new scans
                scanConfig.setKillSwitchEnabled(false);
                killSwitchBtn.setText("Kill Switch OFF");
                if (scanEngine != null) {
                    scanEngine.resetCancelRequested();
                }
            }
        });
        toolbar.add(killSwitchBtn);

        JButton exportBtn = makeToolButton("Copy Report", new Color(50, 120, 180));
        exportBtn.addActionListener(e -> copyReport());
        toolbar.add(exportBtn);

        // Add scan status label to toolbar
        scanStatusLabel = new JLabel(" ● Idle");
        scanStatusLabel.setFont(scanStatusLabel.getFont().deriveFont(Font.BOLD, 11f));
        scanStatusLabel.setForeground(new Color(100, 100, 100));
        toolbar.add(Box.createHorizontalStrut(20));
        toolbar.add(scanStatusLabel);

        rootPanel.add(toolbar, BorderLayout.NORTH);

        // ── Main split: table (top) | details (bottom) ────────────────────
        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mainSplit.setResizeWeight(0.5);
        mainSplit.setContinuousLayout(true);
        mainSplit.setBorder(null);
        // Defer divider location until component is visible
SwingUtilities.invokeLater(() -> mainSplit.setDividerLocation(0.5));

        // Table panel
        findingsTableScrollPane = new JScrollPane(table);
        findingsTableScrollPane.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), " Findings "));
        
        // Auto-scroll behavior: detect manual scrolling to disable auto-scroll
        findingsTableScrollPane.getViewport().addChangeListener(e -> {
            if (!autoScrollEnabled) {
                JViewport viewport = (JViewport) e.getSource();
                JScrollBar verticalBar = findingsTableScrollPane.getVerticalScrollBar();
                if (verticalBar != null) {
                    int bottom = verticalBar.getMaximum() - verticalBar.getVisibleAmount();
                    if (verticalBar.getValue() >= bottom - 5) {
                        autoScrollEnabled = true;
                    }
                }
            }
        });
        
        findingsTableScrollPane.addMouseWheelListener(e -> {
            if (e.getWheelRotation() < 0) {
                autoScrollEnabled = false;
            }
        });
        
        mainSplit.setTopComponent(findingsTableScrollPane);

        // Detail panel
        mainSplit.setBottomComponent(buildDetailPanel());

        rootPanel.add(mainSplit, BorderLayout.CENTER);

        // Add a component listener to set divider to 50% of available space after toolbar
        rootPanel.addComponentListener(new java.awt.event.ComponentAdapter() {
            @Override
            public void componentResized(java.awt.event.ComponentEvent e) {
                // Calculate available height: total height - toolbar height
                int toolbarHeight = toolbar.getPreferredSize().height;
                int availableHeight = rootPanel.getHeight() - toolbarHeight;
                if (availableHeight > 0 && mainSplit.getDividerLocation() != availableHeight / 2) {
                    // Set divider to 50% of available space
                    mainSplit.setDividerLocation(availableHeight / 2);
                }
            }
            
            @Override
            public void componentShown(java.awt.event.ComponentEvent e) {
                // Set initial position when panel becomes visible
                SwingUtilities.invokeLater(() -> {
                    int toolbarHeight = toolbar.getPreferredSize().height;
                    int availableHeight = rootPanel.getHeight() - toolbarHeight;
                    if (availableHeight > 0) {
                        mainSplit.setDividerLocation(availableHeight / 2);
                    }
                });
            }
        });
    }

    private JTable buildTable() {
        JTable t = new JTable(tableModel);
        t.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        t.setRowHeight(22);
        t.setShowGrid(false);
        t.setIntercellSpacing(new Dimension(0, 0));
        t.setFillsViewportHeight(true);
        t.getTableHeader().setReorderingAllowed(false);
        t.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));

        // Only configure columns if the model has columns
        if (tableModel.getColumnCount() > 0) {
            int[] widths = {35, 110, 130, 300, 60, 85, 85, 75, 100};
            for (int i = 0; i < widths.length && i < tableModel.getColumnCount(); i++) {
                t.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
            }

            // Severity colour renderer
            if (tableModel.getColumnCount() > 7) {
                t.getColumnModel().getColumn(7).setCellRenderer(new SeverityRenderer());
            }
        }

        t.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting() && t.getSelectedRow() >= 0) {
                int row = t.convertRowIndexToModel(t.getSelectedRow());
                ScanFinding finding = tableModel.getFindingAtRow(row);
                if (finding != null) {
                    showDetails(finding);
                }
            }
        });

        // Custom sorting for Severity column (index 7)
        TableRowSorter<FindingsTableModel> sorter = new TableRowSorter<>(tableModel);
        t.setRowSorter(sorter);

        // Custom comparator for Severity column
        sorter.setComparator(7, (String a, String b) -> {
            int rankA = a == null ? 0 : 
                        a.contains("High") ? 4 :
                        a.contains("Medium") ? 3 :
                        a.contains("Low") ? 2 :
                        a.contains("Info") ? 1 : 0;
            
            int rankB = b == null ? 0 : 
                        b.contains("High") ? 4 :
                        b.contains("Medium") ? 3 :
                        b.contains("Low") ? 2 :
                        b.contains("Info") ? 1 : 0;
            
            return Integer.compare(rankA, rankB);
        });

        return t;
    }

    private JPanel buildDetailPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // Single tabbed pane containing all detail views
        JTabbedPane detailTabs = new JTabbedPane();
        detailTabs.setFont(detailTabs.getFont().deriveFont(11f));
        
        // Evidence tab
        evidenceArea.setEditable(false);
        evidenceArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        evidenceArea.setBackground(UIManager.getColor("TextArea.background"));
        evidenceArea.setForeground(UIManager.getColor("TextArea.foreground"));
        evidenceArea.setBorder(new EmptyBorder(6, 8, 6, 8));
        JScrollPane evidenceScroll = new JScrollPane(evidenceArea);
        evidenceScroll.getViewport().setBackground(evidenceArea.getBackground());
        detailTabs.addTab("Evidence", evidenceScroll);
        
        // Request & Response tab
        JSplitPane requestResponseSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                requestEditor.uiComponent(), responseEditor.uiComponent());
        requestResponseSplit.setResizeWeight(0.5);
        requestResponseSplit.setContinuousLayout(true);
        requestResponseSplit.setBorder(null);
        detailTabs.addTab("Request & Response", requestResponseSplit);
        
        // Ask AI tab - contains all AI controls
        detailTabs.addTab("Ask AI", buildAskAIPanel());
        
        panel.add(detailTabs, BorderLayout.CENTER);
        panel.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), " Finding Detail "));
        return panel;
    }

    private JPanel buildAskAIPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        
        // Horizontal split: left (prompt + buttons) | right (response)
        JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        mainSplit.setResizeWeight(0.25);
        mainSplit.setContinuousLayout(true);
        mainSplit.setBorder(null);
        
        // Left side: Prompt area with buttons below
        JPanel leftPanel = new JPanel(new BorderLayout());
        leftPanel.setBorder(BorderFactory.createTitledBorder("Prompt"));
        
        aiPromptArea = new JTextArea(12, 40);
        aiPromptArea.setLineWrap(true);
        aiPromptArea.setWrapStyleWord(true);
        aiPromptArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane promptScroll = new JScrollPane(aiPromptArea);
        leftPanel.add(promptScroll, BorderLayout.CENTER);
        
        // Button panel (horizontal below prompt)
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 5));
        buttonPanel.setBorder(BorderFactory.createEmptyBorder(5, 0, 0, 0));
        
        aiSendButton = new JButton("Send");
        aiSendButton.addActionListener(e -> sendAIPrompt());
        buttonPanel.add(aiSendButton);
        
        aiCancelButton = new JButton("Cancel");
        aiCancelButton.setEnabled(false);
        aiCancelButton.addActionListener(e -> cancelAIRequest());
        buttonPanel.add(aiCancelButton);
        
        aiClearButton = new JButton("Clear");
        aiClearButton.addActionListener(e -> clearAIChat());
        buttonPanel.add(aiClearButton);
        
        leftPanel.add(buttonPanel, BorderLayout.SOUTH);
        
        // Right side: Response area
        JPanel rightPanel = new JPanel(new BorderLayout());
        rightPanel.setBorder(BorderFactory.createTitledBorder("Response"));
        
        aiResponseArea = new JTextArea(12, 40);
        aiResponseArea.setEditable(false);
        aiResponseArea.setLineWrap(true);
        aiResponseArea.setWrapStyleWord(true);
        aiResponseArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        aiResponseArea.setText("Click 'Send' to start analysis");
        aiResponseScrollPane = new JScrollPane(aiResponseArea);
        rightPanel.add(aiResponseScrollPane, BorderLayout.CENTER);
        
        mainSplit.setLeftComponent(leftPanel);
        mainSplit.setRightComponent(rightPanel);
        
        panel.add(mainSplit, BorderLayout.CENTER);
        
        return panel;
    }

    private void sendAIPrompt() {
        String prompt = aiPromptArea.getText().trim();
        if (prompt.isEmpty()) {
            return;
        }
        
        if (aiProvider == null || !aiProvider.isAvailable()) {
            aiResponseArea.append("\n[ERROR] AI provider not available. Check settings.\n");
            return;
        }
        
        // Cancel any ongoing request
        if (currentAIWorker != null && !currentAIWorker.isDone()) {
            cancelAIRequest();
        }
        
        // Add user message to conversation history
        currentConversation.addUserMessage(prompt);
        
        // Build context-aware prompt
        String fullPrompt = currentConversation.getConversationContext() + prompt;
        
        // Get provider name
        String providerName = aiProvider.getProviderName();
        
        // Append processing status block
        aiResponseArea.append("\n=================================\n");
        aiResponseArea.append("Analyzing response with " + providerName + "...\n");
        aiResponseArea.append("=================================\n");
        
        // Update UI state
        aiSendButton.setEnabled(false);
        aiCancelButton.setEnabled(true);
        
        // Auto-scroll to bottom (fixed)
        SwingUtilities.invokeLater(() -> {
            if (aiResponseScrollPane != null) {
                JScrollBar vertical = aiResponseScrollPane.getVerticalScrollBar();
                vertical.setValue(vertical.getMaximum());
            }
        });
        
        aiRequestCancelled = false;
        final long startTime = System.currentTimeMillis();
        
        currentAIWorker = new SwingWorker<String, Void>() {
            @Override
            protected String doInBackground() throws Exception {
                return aiProvider.generateText(fullPrompt, Map.of(
                    "temperature", 0.7,
                    "max_tokens", 500
                )).getText();
            }
            
            @Override
            protected void done() {
                long elapsed = System.currentTimeMillis() - startTime;
                
                try {
                    if (aiRequestCancelled || isCancelled()) {
                        // Cancellation handled separately in cancelAIRequest()
                        return;
                    }
                    
                    AIResponse aiResponse = null;
                    String responseText = null;
                    
                    try {
                        // Re-call to get AIResponse with token info
                        aiResponse = aiProvider.generateText(fullPrompt, Map.of(
                            "temperature", 0.7,
                            "max_tokens", 500
                        ));
                        responseText = aiResponse.getText();
                    } catch (Exception e) {
                        // If second call fails, use stored result
                        responseText = get();
                        aiResponse = null;
                    }
                    
                    currentConversation.addAssistantMessage(responseText);
                    
                    // Append completion status block
                    aiResponseArea.append("\n=================================\n");
                    String providerInfo = providerName;
                    if (aiResponse != null && aiResponse.getModel() != null) {
                        providerInfo = providerName + "/" + aiResponse.getModel();
                    }
                    int totalTokens = (aiResponse != null) ? aiResponse.getTotalTokens() : 
                                    (responseText != null ? (int) Math.ceil(responseText.length() / 4.0) : 0);
                    aiResponseArea.append("✓ RESPONSE ANALYSIS COMPLETED\n");
                    aiResponseArea.append("Provider: " + providerInfo + " | Time: " + elapsed + "ms | Tokens: ~" + totalTokens + "\n");
                    aiResponseArea.append("============================================================\n\n");
                    
                    // Append actual response
                    aiResponseArea.append(responseText + "\n");
                    
                    // Append closing separator
                    aiResponseArea.append("=================================\n\n");
                    
                } catch (Exception e) {
                    if (!aiRequestCancelled) {
                        aiResponseArea.append("\n[ERROR]: " + e.getMessage() + "\n\n");
                    }
                } finally {
                    aiSendButton.setEnabled(true);
                    aiCancelButton.setEnabled(false);
                    currentAIWorker = null;
                    
                    // Auto-scroll to bottom (fixed)
                    SwingUtilities.invokeLater(() -> {
                        if (aiResponseScrollPane != null) {
                            JScrollBar vertical = aiResponseScrollPane.getVerticalScrollBar();
                            vertical.setValue(vertical.getMaximum());
                        }
                    });
                }
            }
        };
        
        currentAIWorker.execute();
    }
    
    private void cancelAIRequest() {
        if (currentAIWorker != null && !currentAIWorker.isDone()) {
            // Append cancellation start message
            aiResponseArea.append("\n=================================\n");
            aiResponseArea.append("Cancelling request...\n");
            aiResponseArea.append("=================================\n");
            
            cancelStartTime = System.currentTimeMillis();
            aiRequestCancelled = true;
            currentAIWorker.cancel(true);
            
            // Wait briefly for cancellation to complete
            new Thread(() -> {
                try {
                    // Give the worker a moment to respond to interrupt
                    Thread.sleep(100);
                } catch (InterruptedException ignored) {}
                
                long cancelElapsed = System.currentTimeMillis() - cancelStartTime;
                
                SwingUtilities.invokeLater(() -> {
                    // Append cancellation completion message
                    aiResponseArea.append("=================================\n");
                    aiResponseArea.append("✗ REQUEST CANCELLED\n");
                    aiResponseArea.append("Cancellation time: " + cancelElapsed + "ms\n");
                    aiResponseArea.append("=================================\n\n");
                    
                    // Auto-scroll to bottom (fixed)
                    SwingUtilities.invokeLater(() -> {
                        if (aiResponseScrollPane != null) {
                            JScrollBar vertical = aiResponseScrollPane.getVerticalScrollBar();
                            vertical.setValue(vertical.getMaximum());
                        }
                    });
                });
            }).start();
        }
        
        aiSendButton.setEnabled(true);
        aiCancelButton.setEnabled(false);
    }
    
    private void clearAIChat() {
        int confirm = JOptionPane.showConfirmDialog(rootPanel,
                "Clear conversation history and response?",
                "Clear AI Chat",
                JOptionPane.YES_NO_OPTION);
        if (confirm == JOptionPane.YES_OPTION) {
            currentConversation.clear();
            aiResponseArea.setText("");
            // Optional: keep the prompt area text
        }
    }

    // ── Scan status update ─────────────────────────────────────────────────

    public void updateScanStatus(String status, boolean isScanning) {
        SwingUtilities.invokeLater(() -> {
            if (isScanning) {
                scanStatusLabel.setText(" ● " + status);
                scanStatusLabel.setForeground(new Color(220, 120, 0)); // Orange
            } else {
                scanStatusLabel.setText(" ● Idle");
                scanStatusLabel.setForeground(new Color(100, 100, 100)); // Gray
            }
        });
    }

    // ── Detail population ─────────────────────────────────────────────────

    private void showDetails(ScanFinding f) {
        String host = extractHostFromUrl(f.getUrl());
        String apiPath = extractApiPathFromUrl(f.getUrl());
        int statusCode = f.getResponseStatusCode();
        String statusDisplay = statusCode > 0 ? String.valueOf(statusCode) : "N/A";
        
        evidenceArea.setText(
                "Host:       " + host + "\n"
                + "Method:     " + f.getMethod() + "\n"
                + "API:        " + apiPath + "\n"
                + "Parameter:  " + f.getParamName() + "\n"
                + "Location:   " + f.getParamLocation().label + "\n"
                + "Payload:    " + f.getPayloadUsed() + "\n"
                + "Type:       " + f.getPayloadType().label + "\n"
                + "Confidence: " + f.getConfidenceScore() + "%\n"
                + "Severity:   " + f.getSeverity().icon + " " + f.getSeverity().label + "\n"
                + "Status:     " + statusDisplay + "\n"
                + "Time:       " + f.getTimestamp() + "\n\n"
                + "─── Evidence ─────────────────────────────────────────\n"
                + "  • " + f.getEvidenceSummary().replace("\n", "\n  • ")
        );
        
        // Set request content from raw bytes
        ByteArray rawRequest = f.getRawRequest();
        if (rawRequest != null && rawRequest.length() > 0) {
            try {
                HttpRequest request = HttpRequest.httpRequest(rawRequest);
                requestEditor.setRequest(request);
            } catch (Exception e) {
                requestEditor.setRequest(HttpRequest.httpRequest(""));
                api.logging().logToOutput("[ResultsPanel] Failed to parse request: " + e.getMessage());
            }
        } else {
            requestEditor.setRequest(HttpRequest.httpRequest(""));
        }
        
        // Set response content from raw bytes
        ByteArray rawResponse = f.getRawResponse();
        if (rawResponse != null && rawResponse.length() > 0) {
            try {
                HttpResponse response = HttpResponse.httpResponse(rawResponse);
                responseEditor.setResponse(response);
            } catch (Exception e) {
                responseEditor.setResponse(HttpResponse.httpResponse(""));
                api.logging().logToOutput("[ResultsPanel] Failed to parse response: " + e.getMessage());
            }
        } else {
            responseEditor.setResponse(HttpResponse.httpResponse(""));
        }
        
        evidenceArea.setCaretPosition(0);
        
        // Auto-populate AI prompt with evidence (for report writing)
        if (aiPromptArea != null && f != null) {
            String evidencePreview = f.getEvidenceSummary();
            if (evidencePreview.length() > 800) {
                evidencePreview = evidencePreview.substring(0, 800) + "...";
            }
            aiPromptArea.setText("Act as a senior penetration tester with 10+ years of experience.\n" + //
                "\n" + //
                "Using the findings provided, prepare a complete professional security vulnerability report in bug bounty style and include:\n" + //
                "\n" + //
                "Title\n" + //
                "Severity\n" + //
                "Affected endpoint(s) / parameter(s)\n" + //
                "Vulnerability summary\n" + //
                "Technical description\n" + //
                "Steps to reproduce\n" + //
                "Proof of concept / example request\n" + //
                "Observed behavior\n" + //
                "Security impact\n" + //
                "Risk assessment\n" + //
                "Remediation recommendations\n" + //
                "\n" + //
                "The report should be written in a clear, concise, and professional format suitable for submission to a bug bounty program or security team. Use practical security language, avoid unnecessary filler, and ensure the final report is technically accurate and actionable.\n\n" +
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" +
                "FINDING DETAILS\n" +
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" +
                "Host:       " + host + "\n" +
                "Method:     " + f.getMethod() + "\n" +
                "API:        " + apiPath + "\n" +
                "Parameter:  " + f.getParamName() + "\n" +
                "Location:   " + f.getParamLocation().label + "\n" +
                "Payload:    " + f.getPayloadUsed() + "\n" +
                "Type:       " + f.getPayloadType().label + "\n" +
                "Status:     " + statusDisplay + "\n" +
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" +
                "EVIDENCE\n" +
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" +
                evidencePreview + "\n\n" +
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
            aiPromptArea.setCaretPosition(0);
        }
    }

    private void clearDetails() {
        evidenceArea.setText("");
        requestEditor.setRequest(HttpRequest.httpRequest(""));
        responseEditor.setResponse(HttpResponse.httpResponse(""));
    }

    private String extractHostFromUrl(String url) {
        if (url == null || url.isEmpty()) return "";
        try {
            java.net.URI uri = new java.net.URI(url);
            String scheme = uri.getScheme();
            String host = uri.getHost();
            if (scheme != null && host != null) {
                int port = uri.getPort();
                if (port != -1 && port != (scheme.equals("https") ? 443 : 80)) {
                    return scheme + "://" + host + ":" + port;
                }
                return scheme + "://" + host;
            }
        } catch (Exception e) {
            // Fall through to fallback
        }
        // Fallback: return first part up to third slash
        int endOfHost = url.indexOf("/", 8);
        if (endOfHost != -1) {
            return url.substring(0, endOfHost);
        }
        return url;
    }

    private String extractApiPathFromUrl(String url) {
        if (url == null || url.isEmpty()) return "/";
        try {
            java.net.URI uri = new java.net.URI(url);
            String path = uri.getRawPath();
            String query = uri.getRawQuery();
            if (query != null && !query.isEmpty()) {
                return (path != null ? path : "/") + "?" + query;
            }
            return path != null ? path : "/";
        } catch (Exception e) {
            // Fallback: find path after host
            int afterHost = url.indexOf("/", 8);
            if (afterHost != -1) {
                return url.substring(afterHost);
            }
            return "/";
        }
    }

    // ── Report export ─────────────────────────────────────────────────────

    private void copyReport() {
        List<ScanFinding> findings = model.getFindings();
        if (findings.isEmpty()) {
            JOptionPane.showMessageDialog(rootPanel, "No findings to export.", "SQLi Hunter", JOptionPane.INFORMATION_MESSAGE);
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("SQLi Hunter Report\n");
        sb.append("Generated: ").append(java.time.LocalDateTime.now()).append("\n");
        sb.append("=".repeat(60)).append("\n\n");
        for (int i = 0; i < findings.size(); i++) {
            ScanFinding f = findings.get(i);
            sb.append("Finding #").append(i + 1).append("\n");
            sb.append("  Severity:   ").append(f.getSeverity().label).append("\n");
            sb.append("  URL:        ").append(f.getUrl()).append("\n");
            sb.append("  Method:     ").append(f.getMethod()).append("\n");
            sb.append("  Parameter:  ").append(f.getParamName()).append(" (").append(f.getParamLocation().label).append(")\n");
            sb.append("  Payload:    ").append(f.getPayloadUsed()).append("\n");
            sb.append("  Type:       ").append(f.getPayloadType().label).append("\n");
            sb.append("  Confidence: ").append(f.getConfidenceScore()).append("%\n");
            sb.append("  Evidence:\n    ").append(f.getEvidenceSummary().replace("\n", "\n    ")).append("\n\n");
        }
        Toolkit.getDefaultToolkit().getSystemClipboard()
                .setContents(new StringSelection(sb.toString()), null);
        JOptionPane.showMessageDialog(rootPanel,
                "Report copied to clipboard (" + findings.size() + " findings).",
                "SQLi Hunter", JOptionPane.INFORMATION_MESSAGE);
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    private JButton makeToolButton(String label, Color bg) {
        JButton btn = new JButton(label);
        btn.setBackground(bg);
        btn.setForeground(Color.WHITE);
        btn.setFocusPainted(false);
        btn.setBorderPainted(false);
        btn.setFont(btn.getFont().deriveFont(Font.BOLD, 11f));
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        return btn;
    }

    private AIProvider createAIProviderFromScanConfig() {
        String provider = scanConfig.getActiveAIProvider();
        try {
            if ("ollama".equals(provider)) {
                return new OllamaProvider(
                    scanConfig.getOllamaEndpoint(),
                    scanConfig.getOllamaModel(),
                    scanConfig.getAIConnectTimeout(),
                    scanConfig.getAIReadTimeout(),
                    scanConfig.getAIMaxTokens()
                );
            } else if ("openai".equals(provider)) {
                return new OpenAIProvider(
                    scanConfig.getOpenAIKey(),
                    scanConfig.getOpenAIBaseUrl(),
                    scanConfig.getOpenAIModel(),
                    scanConfig.getAIConnectTimeout(),
                    scanConfig.getAIReadTimeout(),
                    scanConfig.getAIMaxTokens()
                );
            } else if ("claude".equals(provider)) {
                return new ClaudeProvider(
                    scanConfig.getClaudeKey(),
                    scanConfig.getClaudeBaseUrl(),
                    scanConfig.getClaudeModel(),
                    scanConfig.getAIConnectTimeout(),
                    scanConfig.getAIReadTimeout(),
                    scanConfig.getAIMaxTokens()
                );
            }
        } catch (Exception e) {
            api.logging().logToOutput("[ResultsPanel] Failed to create AI provider: " + e.getMessage());
        }
        return null;
    }

    public void refreshAIProvider() {
        this.aiProvider = createAIProviderFromScanConfig();
        if (aiProvider != null && aiProvider.isAvailable()) {
            api.logging().logToOutput("[ResultsPanel] AI provider refreshed: " + aiProvider.getProviderName());
        } else {
            api.logging().logToOutput("[ResultsPanel] AI provider refresh failed - provider not available");
        }
    }

    // ── Table model ───────────────────────────────────────────────────────

    private class FindingsTableModel extends AbstractTableModel {
        private final String[] columns;
        private final java.util.List<Object[]> rows = new java.util.ArrayList<>();
        private final java.util.Map<Integer, ScanFinding> findingMap = new java.util.HashMap<>();

        FindingsTableModel(String[] cols) { 
            this.columns = cols;
        }

        void addFinding(ScanFinding f) {
            int id = f.getTrafficEntryId();
            findingMap.put(id, f);
            
            // Check if this finding should be visible with current filter
            Integer currentFilter = model.getCurrentFilter();
            if (currentFilter != null && currentFilter != id) {
                return; // Not visible under current filter, don't add to UI
            }
            
            // Add single row at the end
            int newRowIndex = rows.size();
            rows.add(new Object[]{
                newRowIndex + 1,                            // # (index 0)
                f.getPayloadType().label,                   // Type (index 1)
                f.getParamName(),                           // Parameter (index 2)
                f.getPayloadUsed(),                         // Payload (index 3)
                f.getResponseStatusCode(),                  // Status (index 4)
                f.getResponseTimeMs(),                      // Time (index 5)
                f.getConfidenceScore(),                     // Confidence (index 6)
                f.getSeverity().icon + " " + f.getSeverity().label,  // Severity (index 7)
                f.getParamLocation().label                  // Location (index 8)
            });
            
            // Incremental insert notification - preserves selection and scroll
            fireTableRowsInserted(newRowIndex, newRowIndex);
        }
        
        void rebuildRows() {
            // Store current selection BEFORE clearing
            int selectedRow = -1;
            ScanFinding selectedFinding = null;
            
            if (table.getSelectedRow() != -1) {
                int viewRow = table.getSelectedRow();
                int modelRow = table.convertRowIndexToModel(viewRow);
                selectedFinding = getFindingAtRow(modelRow);
            }
            
            // Rebuild all rows
            rows.clear();
            java.util.List<ScanFinding> filtered = model.getFilteredFindings();
            for (int i = 0; i < filtered.size(); i++) {
                ScanFinding f = filtered.get(i);
                rows.add(new Object[]{
                        i + 1,
                        f.getPayloadType().label,
                        f.getParamName(),
                        f.getPayloadUsed(),
                        f.getResponseStatusCode(),
                        f.getResponseTimeMs(),
                        f.getConfidenceScore(),
                        f.getSeverity().icon + " " + f.getSeverity().label,
                        f.getParamLocation().label
                });
            }
            
            // Notify table of data change
            fireTableDataChanged();
            
            // Restore selection if the finding still exists
            if (selectedFinding != null) {
                for (int i = 0; i < filtered.size(); i++) {
                    if (filtered.get(i).getTrafficEntryId() == selectedFinding.getTrafficEntryId()) {
                        final int rowToSelect = i;
                        SwingUtilities.invokeLater(() -> {
                            int viewRow = table.convertRowIndexToView(rowToSelect);
                            if (viewRow != -1) {
                                table.setRowSelectionInterval(viewRow, viewRow);
                                table.scrollRectToVisible(table.getCellRect(viewRow, 0, true));
                            }
                        });
                        break;
                    }
                }
            }
        }

        void clear() { 
            rows.clear(); 
            findingMap.clear();
            fireTableDataChanged(); 
        }
        
        ScanFinding getFindingAtRow(int row) {
            java.util.List<ScanFinding> filtered = model.getFilteredFindings();
            if (row >= 0 && row < filtered.size()) {
                return filtered.get(row);
            }
            return null;
        }

        @Override 
        public int getRowCount() { 
            return rows.size(); 
        }
        
        @Override 
        public int getColumnCount() { 
            return columns.length; 
        }
        
        @Override 
        public String getColumnName(int c) { 
            return columns[c]; 
        }
        
        @Override 
        public Object getValueAt(int row, int column) {
            Object[] rowData = rows.get(row);
            if (column == 6 && rowData[6] instanceof Integer) {
                return rowData[6] + "%";
            }
            return rowData[column];
        }
        
        @Override
        public Class<?> getColumnClass(int columnIndex) {
            switch (columnIndex) {
                case 0: return Integer.class;      // # (ID)
                case 4: return Integer.class;      // Status code (HTTP status)
                case 5: return Long.class;         // Time (response time in ms)
                case 6: return Integer.class;      // Confidence score
                default: return String.class;      // Type, Parameter, Payload, Severity, Location
            }
        }
    }

    // ── Severity colour renderer ──────────────────────────────────────────

    private class SeverityRenderer extends DefaultTableCellRenderer {
        @Override
        public Component getTableCellRendererComponent(JTable tbl, Object value,
                                                       boolean selected, boolean focused,
                                                       int row, int col) {
            Component c = super.getTableCellRendererComponent(tbl, value, selected, focused, row, col);
            if (!selected) {
                // Colour based on severity column (col 1)
                try {
                    String sev = (String) tbl.getValueAt(row, 1);
                    if (sev != null && sev.contains("High")) {
                        c.setBackground(new Color(255, 230, 230));
                    } else if (sev != null && sev.contains("Medium")) {
                        c.setBackground(new Color(255, 250, 220));
                    } else if (sev != null && sev.contains("Low")) {
                        c.setBackground(new Color(230, 255, 230));
                    } else {
                        c.setBackground(row % 2 == 0 ? Color.WHITE : new Color(248, 248, 252));
                    }
                } catch (Exception ignored) {
                    c.setBackground(Color.WHITE);
                }
            }
            return c;
        }
    }

    public void filterByTrafficEntry(int trafficEntryId) {
        model.setFilter(trafficEntryId);
    }

    public void clearFilter() {
        model.clearFilter();
    }

    public void onSettingsApplied() {
        refreshAIProvider();
        api.logging().logToOutput("[ResultsPanel] Settings applied - AI provider refreshed");
    }
}