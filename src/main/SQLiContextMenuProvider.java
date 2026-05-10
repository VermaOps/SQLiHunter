package main;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Registers right-click context menu items in Proxy History and Site Map.
 * Provides:
 *   - "SQLi Hunter: Scan This Request"
 *   - "SQLi Hunter: Scan All Selected Requests"
 */
public class SQLiContextMenuProvider implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final ScanEngine scanEngine;
    private final Logging logging;
    private final ApiTrafficModel trafficModel;
    private final ScanConfig config;

    public SQLiContextMenuProvider(MontoyaApi api, ScanEngine engine, Logging logging,
                                    ApiTrafficModel trafficModel, ScanConfig config) {
        this.api = api;
        this.scanEngine = engine;
        this.logging = logging;
        this.trafficModel = trafficModel;
        this.config = config;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> items = new ArrayList<>();

        // Determine selected request(s)
        List<HttpRequestResponse> selected = event.selectedRequestResponses();
        boolean hasRequests = selected != null && !selected.isEmpty();

        if (!hasRequests) return items;

        // ── Separator + header label ───────────────────────────────────────
        items.add(new JSeparator());

        JLabel header = new JLabel("  🔍 SQLi Hunter");
        header.setEnabled(false);
        items.add(header);

        // ── Scan single request ────────────────────────────────────────────
        JMenuItem scanOne = new JMenuItem("Scan This Request");
        scanOne.setToolTipText("Run SQLi Hunter on the selected request");
        scanOne.addActionListener(e -> {
            HttpRequestResponse rr = selected.get(0);
            if (rr == null || rr.request() == null) {
                logging.logToOutput("[SQLiHunter] No valid request selected.");
                return;
            }
                
            // Check HTTP method filter before proceeding
            if (!config.isMethodAllowedForScan(rr.request().method())) {
                logging.logToOutput("[SQLiHunter] Skipping scan for excluded HTTP method: " + rr.request().method() + " " + rr.request().url());
                showNotification("SQLi Hunter: Cannot scan " + rr.request().method() + " requests (excluded by filter)");
                return;
            }
            
            // Check kill switch - prevents manual scans when ON
            if (config.isKillSwitchEnabled()) {
                logging.logToOutput("[SQLiHunter] Kill switch is ON - manual scan blocked for: " + rr.request().method() + " " + rr.request().url());
                showNotification("SQLi Hunter: Kill switch is ON. Turn it OFF to scan.");
                return;
            }

            // Add to API Traffic first
            burp.api.montoya.core.ByteArray rawRequest = rr.request().toByteArray();
            burp.api.montoya.core.ByteArray rawResponse = rr.response() != null ? 
                rr.response().toByteArray() : burp.api.montoya.core.ByteArray.byteArray();
                
            int id = trafficModel.getNextId();
            ApiTrafficEntry entry = new ApiTrafficEntry(
                id,
                rr.request().httpService().host(),
                rr.request().method(),
                rr.request().url(),
                rr.response() != null ? rr.response().statusCode() : 0,
                rawResponse.length(),
                rawRequest,
                rawResponse
            );
            trafficModel.addEntry(entry);
                
            logging.logToOutput("[SQLiHunter] Starting single request scan: "
                    + rr.request().url());
            scanEngine.scanRequest(rr.request(), rr.httpService());
            showNotification("SQLi Hunter: Scanning " + rr.request().url());
        });
        items.add(scanOne);

        // ── Scan all selected requests ─────────────────────────────────────
        if (selected.size() > 1) {
            JMenuItem scanAll = new JMenuItem("Scan All " + selected.size() + " Selected Requests");
            scanAll.setToolTipText("Run SQLi Hunter on all selected requests");
                        scanAll.addActionListener(e -> {
                // Check kill switch before bulk scan
                if (config.isKillSwitchEnabled()) {
                    logging.logToOutput("[SQLiHunter] Kill switch is ON - bulk scan blocked");
                    showNotification("SQLi Hunter: Kill switch is ON. Turn it OFF to scan.");
                    return;
                }
                logging.logToOutput("[SQLiHunter] Starting bulk scan of "
                        + selected.size() + " requests");
                scanEngine.scanRequests(selected);
                showNotification("SQLi Hunter: Scanning " + selected.size() + " requests...");
            });
            items.add(scanAll);
        }

        // ── Cancel running scan ────────────────────────────────────────────
        if (scanEngine.isRunning()) {
            JMenuItem cancel = new JMenuItem("Cancel Running Scan");
            cancel.setForeground(new Color(180, 40, 40));
            cancel.addActionListener(e -> {
                scanEngine.cancelScan();
                showNotification("SQLi Hunter: Scan cancellation requested.");
            });
            items.add(cancel);
        }

        items.add(new JSeparator());
        return items;
    }

    private void showNotification(String message) {
        SwingUtilities.invokeLater(() ->
                JOptionPane.showMessageDialog(null, message, "SQLi Hunter",
                        JOptionPane.INFORMATION_MESSAGE));
    }
}
