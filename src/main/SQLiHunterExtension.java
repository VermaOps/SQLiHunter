package main;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;

/**
 * SQLi Hunter - Burp Suite Extension
 * Automated SQL injection vulnerability finder with smart analysis,
 * context menu integration, and a rich results dashboard.
 */
public class SQLiHunterExtension implements BurpExtension {

    public static final String EXTENSION_NAME = "SQLiHunter";
    public static final String VERSION = "1.0.0";
    public static final String GITHUB_REPO = "https://github.com/VermaOps/SQLiHunter";
    public static final String GITHUB_API_REPO = "https://api.github.com/repos/VermaOps/SQLiHunter";
    public static final String GITHUB_RELEASES_URL = "https://github.com/VermaOps/SQLiHunter/releases";
    private ApiTrafficPanel apiTrafficPanel;
    
    private MontoyaApi api;
    private Logging logging;
    private ScanEngine scanEngine;
    private ResultsPanel resultsPanel;
    private SettingsPanel settingsPanel;
    private ScanConfig scanConfig;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.api.extension().setName("SQLiHunter v" + VERSION);
        this.logging = api.logging();

        logging.logToOutput("===========================================");
        logging.logToOutput(" SQLi Hunter v" + VERSION + " loading...");
        logging.logToOutput("===========================================");

        // Core config (shared across all components)
        scanConfig = new ScanConfig();

        // Results model
        ResultsModel resultsModel = new ResultsModel();
        
        // API Traffic model
        ApiTrafficModel trafficModel = new ApiTrafficModel();  // ADD THIS

        // Scan engine
        scanEngine = new ScanEngine(api, scanConfig, resultsModel, logging, trafficModel);

        // Register Repeater capture handler
        RepeaterCaptureHandler repeaterHandler = new RepeaterCaptureHandler(scanConfig, logging, trafficModel, api);
        api.http().registerHttpHandler(repeaterHandler);
        logging.logToOutput("[SQLiHunter] Repeater capture handler registered.");

        // UI Panels
        resultsPanel = new ResultsPanel(resultsModel, api, scanConfig, scanEngine);
        settingsPanel = new SettingsPanel(scanConfig);
        apiTrafficPanel = new ApiTrafficPanel(trafficModel, api, scanConfig);

        // Link ApiTrafficPanel to ResultsPanel for filtering
        apiTrafficPanel.setResultsPanel(resultsPanel);

        // Link ApiTrafficPanel to ScanEngine for auto-scanning
        apiTrafficPanel.setScanEngine(scanEngine);

        // Set callback for settings changes to refresh traffic table
        settingsPanel.setOnSettingsApplied(() -> {
            apiTrafficPanel.refreshTableFilter();
        });

        // Set callback for AI provider changes to refresh ResultsPanel
        settingsPanel.setOnAIProviderChanged(() -> {
            resultsPanel.onSettingsApplied();
        });

        // Register main tab
        MainTab mainTab = new MainTab(resultsPanel, settingsPanel, apiTrafficPanel);  // MODIFY THIS LINE
        api.userInterface().registerSuiteTab(EXTENSION_NAME, mainTab.getComponent());

        // Register right-click context menu
        api.userInterface().registerContextMenuItemsProvider(
                new SQLiContextMenuProvider(api, scanEngine, logging, trafficModel, scanConfig)
        );

        // Register response highlighter (marks interesting responses in Proxy history)
        api.proxy().registerResponseHandler(
                new ProxyResponseHighlighter(scanConfig, logging, trafficModel, api)  // MODIFY THIS LINE
        );

        logging.logToOutput("SQLi Hunter loaded successfully.");
        logging.logToOutput("Right-click any request in Proxy History or Site Map to scan.");
    }
}
