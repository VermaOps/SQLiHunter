package main;

import burp.api.montoya.core.ByteArray;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Represents a single HTTP request/response pair observed through proxy.
 * Stores raw bytes to preserve binary content and original encoding.
 */
public class ApiTrafficEntry {
    private static final DateTimeFormatter TIME_FORMAT = DateTimeFormatter.ofPattern("HH:mm:ss");
    
    private final int id;
    private final String host;
    private final String method;
    private final String url;
    private final int statusCode;
    private final int responseLength;
    private final String timestamp;
    private ByteArray rawRequest;   // Full raw HTTP request (including headers + body)
    private ByteArray rawResponse;  // Full raw HTTP response (status line + headers + body)
    
    public ApiTrafficEntry(int id, String host, String method, String url,
                           int statusCode, int responseLength, 
                           ByteArray rawRequest, ByteArray rawResponse) {
        this.id = id;
        this.host = host;
        this.method = method;
        this.url = url;
        this.statusCode = statusCode;
        this.responseLength = responseLength;
        this.timestamp = LocalDateTime.now().format(TIME_FORMAT);
        this.rawRequest = rawRequest;
        this.rawResponse = rawResponse;
    }
    
    public int getId() { return id; }
    public String getHost() { return host; }
    public String getMethod() { return method; }
    public String getUrl() { return url; }
    public int getStatusCode() { return statusCode; }
    public int getResponseLength() { return responseLength; }
    public String getTimestamp() { return timestamp; }
    public ByteArray getRawRequest() { return rawRequest; }
    public ByteArray getRawResponse() { return rawResponse; }
    
    // Deprecated - kept for compatibility but returns empty string
    @Deprecated
    public String getRequestPreview() { return ""; }
    
    // Deprecated - kept for compatibility but returns empty string
    @Deprecated
    public String getResponsePreview() { return ""; }
}