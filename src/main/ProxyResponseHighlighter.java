package main;

import burp.api.montoya.MontoyaApi;  // ADD THIS IMPORT
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.proxy.http.*;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;

import java.util.List;
import java.util.regex.*;

/**
 * Passively watches all responses flowing through the Proxy.
 * Highlights responses that contain SQL error signatures with a yellow/red note.
 * This is passive — it does NOT send additional requests.
 */
public class ProxyResponseHighlighter implements ProxyResponseHandler {

    private final ScanConfig config;
    private final Logging logging;
    private final ApiTrafficModel trafficModel;
    private final MontoyaApi api;  // This will now resolve with the import above

    public ProxyResponseHighlighter(ScanConfig config, Logging logging, ApiTrafficModel trafficModel, MontoyaApi api) {
        this.config = config;
        this.logging = logging;
        this.trafficModel = trafficModel;
        this.api = api;
    }

    @Override
    public ProxyResponseReceivedAction handleResponseReceived(
            InterceptedResponse interceptedResponse) {

        try {
            // Capture traffic data regardless of error signatures
            captureTraffic(interceptedResponse);
            
            String body = interceptedResponse.bodyToString();
            if (body == null || body.isBlank()) {
                return ProxyResponseReceivedAction.continueWith(interceptedResponse);
            }

            List<String> matches = findErrorSignatures(body);
            if (!matches.isEmpty()) {
                String note = "⚠️ SQLi signal: " + String.join(", ", matches);
                logging.logToOutput("[PassiveHighlighter] " + note
                        + " in response from " + interceptedResponse.initiatingRequest().url());

                // Create new annotations with highlight and note
                /*burp.api.montoya.core.Annotations annotations = interceptedResponse.annotations()
                        .withHighlightColor(burp.api.montoya.core.HighlightColor.YELLOW)
                        .withNotes(note);

                // Return with modified annotations
                return ProxyResponseReceivedAction.continueWith(interceptedResponse, annotations);
                */
            }
        } catch (Exception e) {
            // Never let the highlighter crash proxy traffic
        }

        return ProxyResponseReceivedAction.continueWith(interceptedResponse);
    }

    @Override
    public ProxyResponseToBeSentAction handleResponseToBeSent(
            InterceptedResponse interceptedResponse) {
        return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
    }

    private List<String> findErrorSignatures(String body) {
        String bodyLower = body.toLowerCase();
        List<String> found = new java.util.ArrayList<>();
        for (String sig : config.getErrorSignatures()) {
            try {
                Pattern p = Pattern.compile(sig, Pattern.CASE_INSENSITIVE);
                if (p.matcher(bodyLower).find()) {
                    found.add(sig);
                    if (found.size() >= 3) break; // cap annotation length
                }
            } catch (PatternSyntaxException ignored) {}
        }
        return found;
    }

    private void captureTraffic(InterceptedResponse interceptedResponse) {
        try {
            var request = interceptedResponse.initiatingRequest();
            
            if (request == null) return;
            
            // Proxy History filter - Proxy responses are always from proxy history
            if (!config.isProxyHistoryEnabled()) {
                return;
            }
            
            // Scope filter
            if (config.isScopeFilterEnabled()) {
                String reqUrl = request.url();
                if (reqUrl != null && !api.scope().isInScope(reqUrl)) {
                    return;
                }
            }

            // Path exclusion filter (check against path only, ignore query parameters)
            String fullUrl = request.url();
            if (fullUrl != null && config.isPathExcludedIgnoreQuery(fullUrl)) {
                return;
            }

            var response = interceptedResponse;
            
            String host = request.httpService().host();
            String method = request.method();
            String url = request.url();
            int statusCode = response.statusCode();
            
            // Capture FULL raw request as bytes (entire HTTP message)
            ByteArray rawRequest = request.toByteArray();
            
            // Capture FULL raw response as bytes (status line + headers + body)
            ByteArray rawResponse = response.toByteArray();
            
            int responseLength = rawResponse.length();
            
            int id = trafficModel.getNextId();
            ApiTrafficEntry entry = new ApiTrafficEntry(id, host, method, url,
                    statusCode, responseLength, rawRequest, rawResponse);
            trafficModel.addEntry(entry);
        } catch (Exception e) {
            // Silently ignore traffic capture errors
            logging.logToOutput("[TrafficCapture] Error: " + e.getMessage());
        }
    }
}