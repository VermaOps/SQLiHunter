package main;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;

import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;
import burp.api.montoya.core.ByteArray;

/**
 * Orchestrates the full scan lifecycle for one or many requests:
 *   1. Extract parameters
 *   2. Establish baselines
 *   3. Inject payloads
 *   4. Analyze responses
 *   5. Record findings
 */
public class ScanEngine {

    private final MontoyaApi api;
    private final ScanConfig config;
    private final ResultsModel results;
    private final Logging logging;
    private final ParameterExtractor extractor;
    private final RequestMutator mutator;
    private final ResponseAnalyzer analyzer;
    private PayloadBuilder payloadBuilder;
    private final ApiTrafficModel trafficModel;

    // Scan status callback interface
    public interface ScanStatusListener {
        void onScanStarted(String url, String method);
        void onScanCompleted(String url, int findingCount);
    }
    private ScanStatusListener statusListener;


    // Track active scan tasks so we can cancel on demand
    private ExecutorService executor;
    private volatile boolean cancelRequested = false;

    public ScanEngine(MontoyaApi api, ScanConfig config,
                    ResultsModel results, Logging logging,
                    ApiTrafficModel trafficModel) {
        this.api = api;
        this.config = config;
        this.results = results;
        this.logging = logging;
        this.trafficModel = trafficModel;
        this.extractor = new ParameterExtractor(config, logging);
        this.mutator = new RequestMutator(logging, config);
        this.analyzer = new ResponseAnalyzer(config);
        this.payloadBuilder = new PayloadBuilder(config);
        this.payloadBuilder.setDatabaseType(config.getDatabaseTypeEnum());
    }

    public void setScanStatusListener(ScanStatusListener listener) {
        this.statusListener = listener;
    }

    // ── Public API ────────────────────────────────────────────────────────

    /** Scan a single request asynchronously. */
    public void scanRequest(HttpRequest request, HttpService service) {
        scanRequest(request, service, -1);
    }

    /** Scan a single request asynchronously with known traffic entry ID. */
    public void scanRequest(HttpRequest request, HttpService service, int knownTrafficEntryId) {

        // Check kill switch first - prevents all scans when ON
        if (config.isKillSwitchEnabled()) {
            logging.logToOutput("[ScanEngine] Kill switch is ON - scan blocked for: " + request.method() + " " + request.url());
            return;
        }

        // Check HTTP method filter before scheduling
        if (!config.isMethodAllowedForScan(request.method())) {
            logging.logToOutput("[ScanEngine] Skipping scan for excluded HTTP method: " + request.method() + " " + request.url());
            return;
        }
        
        cancelRequested = false;
        ensureExecutor();
        final int trafficId = knownTrafficEntryId;
        executor.submit(() -> {
            try {
                scanSingle(request, service, trafficId);
            } catch (Exception e) {
                logging.logToOutput("[ScanEngine] Error scanning request: " + e.getMessage());
            }
        });
    }

    /** Scan multiple requests asynchronously. */
    public void scanRequests(List<HttpRequestResponse> requestResponses) {
        cancelRequested = false;
        ensureExecutor();
        logging.logToOutput("[ScanEngine] Starting bulk scan of " + requestResponses.size() + " requests");
        for (HttpRequestResponse rr : requestResponses) {
            executor.submit(() -> {
                try {
                    scanSingle(rr.request(), rr.httpService(), -1);
                } catch (Exception e) {
                    logging.logToOutput("[ScanEngine] Error: " + e.getMessage());
                }
            });
        }
    }

    /** Request cancellation of any running scan. */
    public void cancelScan() {
        cancelRequested = true;
        logging.logToOutput("[ScanEngine] Scan cancellation requested.");
    }

    public void resetCancelRequested() {
        cancelRequested = false;
        logging.logToOutput("[ScanEngine] Cancel flag reset.");
    }

    public boolean isRunning() {
        return executor != null && !executor.isTerminated() && !executor.isShutdown();
    }

    // ── Core scan logic ───────────────────────────────────────────────────

    private void scanSingle(HttpRequest request, HttpService service, int knownTrafficEntryId) {
        String url = request.url();
        if (config.isPathExcludedIgnoreQuery(url)) {
            logging.logToOutput("[ScanEngine] Skipping excluded path: " + url);
            return;
        }

        logging.logToOutput("[ScanEngine] Scanning: " + request.method() + " " + url);
        if (statusListener != null) {
            statusListener.onScanStarted(url, request.method());
        }
        results.incrementScanned();

        List<ParameterExtractor.ExtractedParam> params = extractor.extract(request);
        if (params.isEmpty()) {
            logging.logToOutput("[ScanEngine] No injectable parameters found.");
            return;
        }

        // Force payload builder to use current config (defensive)
        payloadBuilder = new PayloadBuilder(config);
        payloadBuilder.setDatabaseType(config.getDatabaseTypeEnum());
        List<PayloadBuilder.Payload> payloads = payloadBuilder.buildPayloads();
        if (payloads.isEmpty()) {
            logging.logToOutput("[ScanEngine] No payloads generated for " + request.url() + " - check scan configuration");
            return;
        }

        logging.logToOutput("[ScanEngine] Generated " + payloads.size() + " payloads for scanning");

        for (ParameterExtractor.ExtractedParam param : params) {
            if (cancelRequested) {
                logging.logToOutput("[ScanEngine] Scan cancelled.");
                return;
            }

            logging.logToOutput("[ScanEngine]   Testing param: " + param);

            // Establish baseline
            BaselineResult baseline = establishBaseline(request);
            if (baseline == null) continue;

            for (PayloadBuilder.Payload payload : payloads) {
                if (cancelRequested) return;

                delay();

                HttpRequest mutated = mutator.inject(request, param, payload.value);
                results.incrementRequests(1);

                try {
                    long start = System.currentTimeMillis();
                    // Send the mutated request - it carries its own HttpService
                    HttpRequestResponse rr = api.http().sendRequest(mutated);
                    long elapsed = System.currentTimeMillis() - start;

                    HttpResponse response = rr.response();
                    ResponseAnalyzer.AnalysisResult result;

                    if (payload.type == PayloadBuilder.PayloadType.TIME_BASED) {
                        result = analyzer.analyzeTimeBased(baseline.responseTimeMs, elapsed, payload);
                    } else {
                        result = analyzer.analyzeErrorOrBoolean(baseline.response, response, payload);

                        // For boolean-based: also send the "true" variant for comparison
                        if (payload.type == PayloadBuilder.PayloadType.BOOLEAN_BASED
                                && payload.booleanTrueVariant != null) {
                            HttpRequest trueRequest = mutator.inject(request, param, payload.booleanTrueVariant);
                            HttpRequestResponse trueRR = api.http().sendRequest(trueRequest);
                            // Re-analyze with true/false comparison
                            result = analyzer.analyzeErrorOrBoolean(trueRR.response(), response, payload);
                            results.incrementRequests(1);
                        }
                    }

                    if (result.isInteresting) {
                        String evidence = String.join("\n  • ", result.evidence);
                        
                        // Capture FULL raw request as bytes (entire HTTP message with payload injected)
                        ByteArray rawRequest = mutated.toByteArray();
                        
                        // Capture FULL raw response as bytes (status line + headers + body)
                        ByteArray rawResponse = response != null ? response.toByteArray() : ByteArray.byteArray();
                        
                        // Use provided traffic entry ID if available (from auto-scan), otherwise fall back to lookup
                        int trafficEntryId = knownTrafficEntryId;
                        if (trafficEntryId == -1) {
                            for (ApiTrafficEntry entry : trafficModel.getEntries()) {
                                if (entry.getUrl().equals(url) && entry.getMethod().equals(request.method())) {
                                    trafficEntryId = entry.getId();
                                    break;
                                }
                            }
                        }

                        int statusCode = response != null ? response.statusCode() : 0;
                        ScanFinding finding = new ScanFinding(
                                url, request.method(),
                                param.name, param.location,
                                payload.value, payload.type,
                                result.confidenceScore,
                                evidence,
                                rawRequest, rawResponse,
                                trafficEntryId,
                                statusCode,
                                elapsed
                        );
                        results.addFinding(finding);

                        logging.logToOutput(String.format(
                                "[FINDING] %s | Param: %s | Payload: %s | Confidence: %d%%",
                                url, param.name, payload.value, result.confidenceScore));
                    }

                } catch (Exception e) {
                    logging.logToOutput("[ScanEngine] Request failed for payload '"
                            + payload.value + "': " + e.getMessage());
                }
            }
        }

        logging.logToOutput("[ScanEngine] Done scanning: " + url);
        if (statusListener != null) {
            // Count findings for this URL
            int findingCount = 0;
            for (ApiTrafficEntry entry : trafficModel.getEntries()) {
                if (entry.getUrl().equals(url)) {
                    for (ScanFinding f : results.getFindings()) {
                        if (f.getTrafficEntryId() == entry.getId()) {
                            findingCount++;
                        }
                    }
                    break;
                }
            }
            statusListener.onScanCompleted(url, findingCount);
        }
    }

    // ── Baseline measurement ──────────────────────────────────────────────

    private static class BaselineResult {
        HttpResponse response;
        long responseTimeMs;
        BaselineResult(HttpResponse r, long ms) { response = r; responseTimeMs = ms; }
    }

    private BaselineResult establishBaseline(HttpRequest request) {
        try {
            long start = System.currentTimeMillis();
            // Send the original request - it carries its own HttpService
            HttpRequestResponse rr = api.http().sendRequest(request);
            long elapsed = System.currentTimeMillis() - start;
            return new BaselineResult(rr.response(), elapsed);
        } catch (Exception e) {
            logging.logToOutput("[ScanEngine] Baseline request failed: " + e.getMessage());
            return null;
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    private void delay() {
        int ms = config.getRequestDelayMs();
        if (ms > 0) {
            try { Thread.sleep(ms); }
            catch (InterruptedException e) { Thread.currentThread().interrupt(); }
        }
    }

    private void ensureExecutor() {
        if (executor == null || executor.isShutdown()) {
            executor = Executors.newCachedThreadPool();
        }
    }
}