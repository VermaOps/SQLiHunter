package main;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.util.List;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.http.HttpService;

/**
 * API Traffic panel showing all proxied HTTP requests/responses.
 */
public class ApiTrafficPanel {
    
    private final ApiTrafficModel model;
    private final MontoyaApi api;  // ADD THIS - need API reference
    private final Logging logging;
    private final ScanConfig scanConfig;
    private ResultsPanel resultsPanel;
    private ScanEngine scanEngine;
    private final String[] COLUMNS = {"#", "Host", "Method", "URL", "Status", "Length"};
    private final TrafficTableModel tableModel;
    private final JTable table;
    private final HttpRequestEditor requestEditor;  // CHANGED from JTextArea
    private final HttpResponseEditor responseEditor;  // CHANGED from JTextArea
    private JPanel rootPanel;
    
    public ApiTrafficPanel(ApiTrafficModel model, MontoyaApi api, ScanConfig scanConfig) {
        this.model = model;
        this.api = api;
        this.logging = api.logging();
        this.scanConfig = scanConfig;
        this.tableModel = new TrafficTableModel();
        this.table = buildTable();
        // Create Burp's native editors which automatically adapt to theme
        this.requestEditor = api.userInterface().createHttpRequestEditor();
        this.responseEditor = api.userInterface().createHttpResponseEditor();
        buildUI();
        
        model.addListener(new ApiTrafficModel.Listener() {
            @Override
            public void onEntryAdded(ApiTrafficEntry entry) {
                SwingUtilities.invokeLater(() -> {
                    if (shouldDisplayEntry(entry)) {
                        tableModel.addEntry(entry);
                        
                        // Auto-scan this request if ScanEngine is available and method is allowed
                        if (scanEngine != null && !scanConfig.isKillSwitchEnabled() && scanConfig.isMethodAllowedForScan(entry.getMethod())) {
                            final int trafficEntryId = entry.getId();  // Capture ID for use in thread
                            new Thread(() -> {
                                try {
                                    HttpRequest request = HttpRequest.httpRequest(entry.getRawRequest());
                                    // Create HttpService from the stored URL
                                    String url = entry.getUrl();
                                    java.net.URI uri = new java.net.URI(url);
                                    String scheme = uri.getScheme();
                                    String host = uri.getHost();
                                    int port = uri.getPort();
                                    if (port == -1) {
                                        port = scheme.equals("https") ? 443 : 80;
                                    }
                                    boolean useHttps = scheme.equalsIgnoreCase("https");
                                    HttpService httpService = HttpService.httpService(host, port, useHttps);
                                    // CRITICAL FIX: Attach HttpService to the request
                                    request = request.withService(httpService);
                                    scanEngine.scanRequest(request, httpService, trafficEntryId);  // Pass ID directly
                                    logging.logToOutput("[ApiTrafficPanel] Auto-scan started: " + entry.getMethod() + " " + entry.getUrl() + " (traffic ID: " + trafficEntryId + ")");
                                } catch (Exception e) {
                                    logging.logToOutput("[ApiTrafficPanel] Auto-scan failed: " + e.getMessage());
                                }
                            }).start();
                        }
                    }
                });
            }
            @Override
            public void onCleared() {
                SwingUtilities.invokeLater(() -> {
                    tableModel.clear();
                    clearDetails();
                });
            }
        });
    }
    
    public void setScanEngine(ScanEngine engine) {
        this.scanEngine = engine;
        if (engine != null && resultsPanel != null) {
            engine.setScanStatusListener(new ScanEngine.ScanStatusListener() {
                @Override
                public void onScanStarted(String url, String method) {
                    // Find entry ID for this URL and notify ResultsPanel
                    for (ApiTrafficEntry entry : model.getEntries()) {
                        if (entry.getUrl().equals(url) && entry.getMethod().equals(method)) {
                            SwingUtilities.invokeLater(() -> {
                                // If this entry is currently selected, update status
                                int selectedRow = table.getSelectedRow();
                                if (selectedRow >= 0) {
                                    int modelRow = table.convertRowIndexToModel(selectedRow);
                                    ApiTrafficEntry selectedEntry = model.getEntries().get(modelRow);
                                    if (selectedEntry.getId() == entry.getId() && resultsPanel != null) {
                                        resultsPanel.updateScanStatus("Scanning: " + method + " " + truncateUrl(url), true);
                                    }
                                }
                            });
                            break;
                        }
                    }
                }
                
                @Override
                public void onScanCompleted(String url, int findingCount) {
                    // Find entry ID for this URL and notify ResultsPanel
                    for (ApiTrafficEntry entry : model.getEntries()) {
                        if (entry.getUrl().equals(url)) {
                            SwingUtilities.invokeLater(() -> {
                                // If this entry is currently selected, update status
                                int selectedRow = table.getSelectedRow();
                                if (selectedRow >= 0) {
                                    int modelRow = table.convertRowIndexToModel(selectedRow);
                                    ApiTrafficEntry selectedEntry = model.getEntries().get(modelRow);
                                    if (selectedEntry.getId() == entry.getId() && resultsPanel != null) {
                                        resultsPanel.updateScanStatus("Complete - " + findingCount + " finding" + (findingCount != 1 ? "s" : ""), false);
                                    }
                                }
                            });
                            break;
                        }
                    }
                }
            });
        }
    }

    public JPanel getPanel() { return rootPanel; }
    
    private void buildUI() {
        rootPanel = new JPanel(new BorderLayout(0, 0));
        rootPanel.setBackground(Color.WHITE);
        
        // Toolbar
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 6));
        toolbar.setBackground(new Color(30, 30, 50));
        JButton clearBtn = new JButton("Clear Traffic");
        clearBtn.setBackground(new Color(180, 60, 60));
        clearBtn.setForeground(Color.WHITE);
        clearBtn.setFocusPainted(false);
        clearBtn.setBorderPainted(false);
        clearBtn.setFont(clearBtn.getFont().deriveFont(Font.BOLD, 11f));
        clearBtn.addActionListener(e -> {
            int confirm = JOptionPane.showConfirmDialog(rootPanel,
                    "Clear all traffic entries?", "Confirm", JOptionPane.YES_NO_OPTION);
            if (confirm == JOptionPane.YES_OPTION) model.clear();
        });
        toolbar.add(clearBtn);
        rootPanel.add(toolbar, BorderLayout.NORTH);
        
        // Main split: table (top) | details (bottom)
        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        mainSplit.setResizeWeight(0.5);
        mainSplit.setContinuousLayout(true);
        mainSplit.setBorder(null);
        
        JScrollPane tableScroll = new JScrollPane(table);
        tableScroll.setBorder(BorderFactory.createTitledBorder(
                BorderFactory.createEtchedBorder(), " API Traffic "));
        mainSplit.setTopComponent(tableScroll);
        mainSplit.setBottomComponent(buildDetailPanel());
        
        rootPanel.add(mainSplit, BorderLayout.CENTER);
        // Add a component listener to set divider to 50% of available space after toolbar
        rootPanel.addComponentListener(new java.awt.event.ComponentAdapter() {
            @Override
            public void componentResized(java.awt.event.ComponentEvent e) {
                // Calculate available height: total height - toolbar height
                int toolbarHeight = toolbar.getPreferredSize().height;
                int availableHeight = rootPanel.getHeight() - toolbarHeight;
                if (availableHeight > 0) {
                    // Set divider to 50% of available space
                    mainSplit.setDividerLocation(availableHeight / 2);
                }
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
        
        int[] widths = {40, 180, 60, 350, 60, 70};
        for (int i = 0; i < widths.length; i++) {
            t.getColumnModel().getColumn(i).setPreferredWidth(widths[i]);
        }
        
        t.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting() && t.getSelectedRow() >= 0) {
                int visibleRow = t.getSelectedRow();
                ApiTrafficEntry entry = tableModel.getEntryAtRow(visibleRow);
                if (entry != null) {
                    showDetails(entry);
                    if (resultsPanel != null) {
                        resultsPanel.filterByTrafficEntry(entry.getId());
                    }
                }
            }
        });
        
        t.setAutoCreateRowSorter(true);
        return t;
    }
    
    private JPanel buildDetailPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        JTabbedPane tabs = new JTabbedPane();
        tabs.setFont(tabs.getFont().deriveFont(11f));
        
        // Burp's native editors automatically adapt to light/dark theme
        tabs.addTab("Request", requestEditor.uiComponent());
        tabs.addTab("Response", responseEditor.uiComponent());
        
        panel.add(tabs, BorderLayout.CENTER);
        return panel;
    }
    
    private void showDetails(ApiTrafficEntry entry) {
        // Set request content from raw bytes
        ByteArray rawRequest = entry.getRawRequest();
        if (rawRequest != null && rawRequest.length() > 0) {
            try {
                HttpRequest request = HttpRequest.httpRequest(rawRequest);
                requestEditor.setRequest(request);
            } catch (Exception e) {
                // If parsing fails, create a basic request
                requestEditor.setRequest(HttpRequest.httpRequest(""));
                logging.logToOutput("[ApiTrafficPanel] Failed to parse request: " + e.getMessage());
            }
        } else {
            requestEditor.setRequest(HttpRequest.httpRequest(""));
        }
        
        // Set response content from raw bytes
        ByteArray rawResponse = entry.getRawResponse();
        if (rawResponse != null && rawResponse.length() > 0) {
            try {
                HttpResponse response = HttpResponse.httpResponse(rawResponse);
                responseEditor.setResponse(response);
            } catch (Exception e) {
                // If parsing fails, create a basic response
                responseEditor.setResponse(HttpResponse.httpResponse(""));
                logging.logToOutput("[ApiTrafficPanel] Failed to parse response: " + e.getMessage());
            }
        } else {
            responseEditor.setResponse(HttpResponse.httpResponse(""));
        }
    }

    private void clearDetails() {
        requestEditor.setRequest(HttpRequest.httpRequest(""));
        responseEditor.setResponse(HttpResponse.httpResponse(""));
    }
    
    /**
     * Refreshes the traffic table display to respect current HTTP method filters.
     * Called when settings change.
     */
    public void refreshTableFilter() {
        SwingUtilities.invokeLater(() -> {
            tableModel.refreshRows();
            // Clear selection and details if current selection is now filtered out
            int selectedRow = table.getSelectedRow();
            if (selectedRow >= 0) {
                int modelRow = table.convertRowIndexToModel(selectedRow);
                if (modelRow >= tableModel.getRowCount()) {
                    table.clearSelection();
                    clearDetails();
                    if (resultsPanel != null) {
                        resultsPanel.clearFilter();
                    }
                }
            }
        });
    }

    private boolean shouldDisplayEntry(ApiTrafficEntry entry) {
        String method = entry.getMethod().toUpperCase();
        
        // Handle OPTIONS exclusion
        if (scanConfig.isExcludeOptions() && "OPTIONS".equals(method)) {
            return false;
        }
        
        // Filter by enabled HTTP methods
        boolean allowed = false;
        switch (method) {
            case "GET": allowed = scanConfig.isMethodGetEnabled(); break;
            case "POST": allowed = scanConfig.isMethodPostEnabled(); break;
            case "PUT": allowed = scanConfig.isMethodPutEnabled(); break;
            case "PATCH": allowed = scanConfig.isMethodPatchEnabled(); break;
            case "DELETE": allowed = scanConfig.isMethodDeleteEnabled(); break;
            default: allowed = false; break;
        }
        
        if (!allowed) {
            return false;
        }
        
        // Path exclusion filter (check against path only, ignore query parameters)
        String entryUrl = entry.getUrl();
        if (entryUrl != null && scanConfig.isPathExcludedIgnoreQuery(entryUrl)) {
            return false;
        }
        
        return true;
    }

    private class TrafficTableModel extends AbstractTableModel {
        private final java.util.List<Object[]> rows = new java.util.ArrayList<>();
        private final java.util.List<ApiTrafficEntry> entriesAtRows = new java.util.ArrayList<>();
        
        void addEntry(ApiTrafficEntry entry) {
            // Extract only the path + query from the full URL
            String fullUrl = entry.getUrl();
            String pathOnly = extractPath(fullUrl);
            
            rows.add(new Object[]{
                    entry.getId(),
                    entry.getHost(),
                    entry.getMethod(),
                    truncate(pathOnly, 80),
                    entry.getStatusCode(),
                    entry.getResponseLength()
            });
            entriesAtRows.add(entry);
            fireTableRowsInserted(rows.size() - 1, rows.size() - 1);
        }
        
        void clear() { 
            rows.clear(); 
            entriesAtRows.clear();
            fireTableDataChanged(); 
        }
        
        private String truncate(String s, int max) {
            return s.length() <= max ? s : s.substring(0, max) + "...";
        }
        
        void refreshRows() {
            // Rebuild rows based on current filter
            rows.clear();
            entriesAtRows.clear();
            for (ApiTrafficEntry entry : model.getEntries()) {
                if (shouldDisplayEntry(entry)) {
                    String fullUrl = entry.getUrl();
                    String pathOnly = extractPath(fullUrl);
                    rows.add(new Object[]{
                            entry.getId(),
                            entry.getHost(),
                            entry.getMethod(),
                            truncate(pathOnly, 80),
                            entry.getStatusCode(),
                            entry.getResponseLength()
                    });
                    entriesAtRows.add(entry);
                }
            }
            fireTableDataChanged();
        }
        
        ApiTrafficEntry getEntryAtRow(int filteredRowIndex) {
            if (filteredRowIndex >= 0 && filteredRowIndex < entriesAtRows.size()) {
                return entriesAtRows.get(filteredRowIndex);
            }
            return null;
        }

        @Override 
        public int getRowCount() { 
            return rows.size(); 
        }
        
        @Override 
        public int getColumnCount() { 
            return COLUMNS.length; 
        }
        
        @Override 
        public String getColumnName(int c) { 
            return COLUMNS[c]; 
        }
        
        @Override 
        public Object getValueAt(int r, int c) { 
            return rows.get(r)[c]; 
        }

        @Override 
        public Class<?> getColumnClass(int columnIndex) {
            switch (columnIndex) {
                case 0: return Integer.class;      // # (ID)
                case 4: return Integer.class;      // Status code
                case 5: return Integer.class;      // Response Length
                default: return String.class;      // Host, Method, URL
            }
        }
    }

    private String extractPath(String fullUrl) {
        if (fullUrl == null || fullUrl.isEmpty()) {
            return "";
        }
        try {
            java.net.URI uri = new java.net.URI(fullUrl);
            String path = uri.getRawPath();
            String query = uri.getRawQuery();
            if (query != null && !query.isEmpty()) {
                return path + "?" + query;
            }
            return path != null ? path : "/";
        } catch (Exception e) {
            // Fallback: try to extract after the third slash
            int afterHost = fullUrl.indexOf("/", 8); // skip http:// or https://
            if (afterHost != -1) {
                return fullUrl.substring(afterHost);
            }
            return fullUrl;
        }
    }

    private String truncateUrl(String url) {
        if (url == null) return "";
        if (url.length() <= 60) return url;
        return url.substring(0, 57) + "...";
    }

    public void setResultsPanel(ResultsPanel panel) {
        this.resultsPanel = panel;
    }
}