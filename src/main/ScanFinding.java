package main;

import burp.api.montoya.core.ByteArray;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Represents a single potential SQL injection finding.
 * Stores raw bytes to preserve binary content and original encoding.
 */
public class ScanFinding {

    public enum Severity {
        HIGH("High", "🔴"),
        MEDIUM("Medium", "🟡"),
        LOW("Low", "🟢"),
        INFO("Info", "⚪");

        public final String label;
        public final String icon;
        Severity(String label, String icon) { this.label = label; this.icon = icon; }
    }

    private final String url;
    private final String method;
    private final String paramName;
    private final ParameterExtractor.ParamLocation paramLocation;
    private final String payloadUsed;
    private final PayloadBuilder.PayloadType payloadType;
    private final int confidenceScore;
    private final Severity severity;
    private final String evidenceSummary;
    private final String timestamp;
    private final int trafficEntryId;
    private final int responseStatusCode;
    private final long responseTimeMs;
    private ByteArray rawRequest;   // Full raw HTTP request (mutated request with payload)
    private ByteArray rawResponse;  // Full raw HTTP response (status line + headers + body)

    public ScanFinding(String url, String method, String paramName,
                       ParameterExtractor.ParamLocation location,
                       String payload, PayloadBuilder.PayloadType payloadType,
                       int confidence, String evidence,
                       ByteArray rawRequest, ByteArray rawResponse, int trafficEntryId,
                       int responseStatusCode, long responseTimeMs) {
        this.url = url;
        this.method = method;
        this.paramName = paramName;
        this.paramLocation = location;
        this.payloadUsed = payload;
        this.payloadType = payloadType;
        this.confidenceScore = confidence;
        this.severity = scoreTOSeverity(confidence);
        this.evidenceSummary = evidence;
        this.timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"));
        this.rawRequest = rawRequest;
        this.rawResponse = rawResponse;
        this.trafficEntryId = trafficEntryId;
        this.responseStatusCode = responseStatusCode;
        this.responseTimeMs = responseTimeMs;
    }

    private static Severity scoreTOSeverity(int score) {
        if (score >= 75) return Severity.HIGH;
        if (score >= 50) return Severity.MEDIUM;
        if (score >= 25) return Severity.LOW;
        return Severity.INFO;
    }

    // ── Getters ─────────────────────────────────────────────────────────────

    public String getUrl() { return url; }
    public String getMethod() { return method; }
    public String getParamName() { return paramName; }
    public ParameterExtractor.ParamLocation getParamLocation() { return paramLocation; }
    public String getPayloadUsed() { return payloadUsed; }
    public PayloadBuilder.PayloadType getPayloadType() { return payloadType; }
    public int getConfidenceScore() { return confidenceScore; }
    public Severity getSeverity() { return severity; }
    public String getEvidenceSummary() { return evidenceSummary; }
    public String getTimestamp() { return timestamp; }
    public ByteArray getRawRequest() { return rawRequest; }
    public ByteArray getRawResponse() { return rawResponse; }
    public int getTrafficEntryId() { return trafficEntryId; }
    public int getResponseStatusCode() { return responseStatusCode; }
    public long getResponseTimeMs() { return responseTimeMs; }
    
    // Deprecated - kept for compatibility but returns empty string
    @Deprecated
    public String getRequestPreview() { return ""; }
    
    // Deprecated - kept for compatibility but returns empty string
    @Deprecated
    public String getResponsePreview() { return ""; }

    /** Short one-line description for table display. */
    public String getShortDescription() {
        return String.format("[%s] %s @ %s (%s) | Confidence: %d%%",
                payloadType.icon, paramName, url, paramLocation.label, confidenceScore);
    }
}