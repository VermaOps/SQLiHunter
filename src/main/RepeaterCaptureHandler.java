package main;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;

public class RepeaterCaptureHandler implements HttpHandler {
    
    private final ScanConfig config;
    private final Logging logging;
    private final ApiTrafficModel trafficModel;
    private final MontoyaApi api;
    
    public RepeaterCaptureHandler(ScanConfig config, Logging logging, 
                                   ApiTrafficModel trafficModel, MontoyaApi api) {
        this.config = config;
        this.logging = logging;
        this.trafficModel = trafficModel;
        this.api = api;
    }
    
    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
        return RequestToBeSentAction.continueWith(requestToBeSent);
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
        try {
            // Check if this is from Repeater
            if (!responseReceived.toolSource().isFromTool(burp.api.montoya.core.ToolType.REPEATER)) {
                return ResponseReceivedAction.continueWith(responseReceived);
            }
            
            // Check if Repeater capture is enabled
            if (!config.isRepeaterEnabled()) {
                return ResponseReceivedAction.continueWith(responseReceived);
            }
            
            var request = responseReceived.initiatingRequest();
            if (request == null) {
                return ResponseReceivedAction.continueWith(responseReceived);
            }
            
            // Scope filter
            if (config.isScopeFilterEnabled()) {
                String url = request.url();
                if (url != null && !api.scope().isInScope(url)) {
                    return ResponseReceivedAction.continueWith(responseReceived);
                }
            }
            
            // Path exclusion filter (check against path only, ignore query parameters)
            String fullUrl = request.url();
            if (fullUrl != null && config.isPathExcludedIgnoreQuery(fullUrl)) {
                return ResponseReceivedAction.continueWith(responseReceived);
            }

            // Capture the request and response
            String host = request.httpService().host();
            String method = request.method();
            String url = request.url();
            int statusCode = responseReceived.statusCode();
            
            ByteArray rawRequest = request.toByteArray();
            ByteArray rawResponse = responseReceived.toByteArray();
            int responseLength = rawResponse.length();
            
            int id = trafficModel.getNextId();
            ApiTrafficEntry entry = new ApiTrafficEntry(id, host, method, url,
                    statusCode, responseLength, rawRequest, rawResponse);
            trafficModel.addEntry(entry);
            
            logging.logToOutput("[RepeaterCapture] Captured: " + method + " " + url);
            
        } catch (Exception e) {
            logging.logToOutput("[RepeaterCapture] Error: " + e.getMessage());
        }
        
        return ResponseReceivedAction.continueWith(responseReceived);
    }
}