package main;

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Holds all user-configurable scan settings. Shared across UI and engine.
 */
public class ScanConfig {

    // ── Payload categories ──────────────────────────────────────────────────
    private boolean enableErrorBased = true;
    private boolean enableBooleanBased = true;
    private boolean enableTimeBased = true;
    private boolean enableUnionBased = false; // noisier, off by default

    // ── Target selection ────────────────────────────────────────────────────
    private boolean scanUrlParams = true;
    private boolean scanBodyParams = true;
    private boolean scanHeaders = false;       // opt-in – can be very noisy
    private boolean scanCookies = false;
    private boolean scanJsonBody = true;
    private boolean scanXmlBody = true;
    private boolean testHiddenParams = true;   // common names heuristic

    // ── Scan mode ──────────────────────────────────────────────────────────
    private boolean useCustomOnly = false;     // true = CUSTOM mode (only custom payloads), false = AUTOMATED mode (use payload types)

    // ── Rate limiting / impact reduction ───────────────────────────────────
    private int requestDelayMs = 200;          // pause between payloads
    private int timeoutMs = 10000;
    //private int threadPoolSize = 3;

    // ── Detection thresholds ───────────────────────────────────────────────
    private int minConfidenceScore = 0;       // 0-100; lower → more FPs
    private double timingMultiplier = 0;     // response must be Nx the baseline
    private int timingBaselineSleepSec = 6;

    // ── HTTP Method Filtering ────────────────────────────────────────────
    private boolean methodGetEnabled = true;
    private boolean methodPostEnabled = true;
    private boolean methodPutEnabled = true;
    private boolean methodPatchEnabled = true;
    private boolean methodDeleteEnabled = true;
    private boolean excludeOptions = true;

    // ── Traffic Source Filters ────────────────────────────────────────────
    private boolean proxyHistoryEnabled = true;
    private boolean scopeFilterEnabled = true;
    private boolean repeaterEnabled = true;

    // ── Exclusions ─────────────────────────────────────────────────────────
    private final List<String> excludedParams = new CopyOnWriteArrayList<>(
            Arrays.asList("csrf", "token", "__viewstate", "_wpnonce")
    );
    private final List<String> excludedPaths = new CopyOnWriteArrayList<>(
        Arrays.asList("\\.(js|css|png|jpg|jpeg|gif|svg|ico|webp|bmp|tiff|woff2?|ttf|eot|otf|pdf|zip|tar\\.gz|tgz|rar|7z|mp[34]|webm|avi|mov|flv|wmv|txt|csv|xml|json|min\\.js|min\\.css)(?:[\\?#].*)?$")
    );

    // ── Kill Switch ────────────────────────────────────────────────────────
    private boolean killSwitchEnabled = false;   // false = OFF (scanning allowed), true = ON (scanning blocked)

    // ── Custom payloads ────────────────────────────────────────────────────
    private String customPayloads = "";        // newline-separated

    // ── Error signatures ───────────────────────────────────────────────────
    // Patterns that indicate a SQL error in the response body
    private final List<String> errorSignatures = new CopyOnWriteArrayList<>(Arrays.asList(
            // MySQL / MariaDB
            "you have an error in your sql syntax",
            "sql syntax.*near",
            "warning: mysql",
            "mysql_fetch_array",
            "supplied argument is not a valid mysql",
            // Microsoft SQL Server
            "unclosed quotation mark",
            "quoted string not properly terminated",
            "incorrect syntax near '",
            "[sql server]",
            "microsoft ole db provider for sql server",
            "[microsoft][odbc sql server driver]",
            // Oracle
            "ora-\\d{5}",
            // PostgreSQL
            "pg::syntaxerror",
            "pg_query",
            // SQLite
            "sqlite3::exception",
            "sqlite error",
            // Generic SQL errors (with context requirements enforced in analyzer)
            "sqlexception",
            "unexpected end of sql command",
            "db2 sql error",
            "dynamic sql error",
            "data source name not found"
    ));

    // ── Common hidden parameter names ──────────────────────────────────────
    private final List<String> hiddenParamNames = new CopyOnWriteArrayList<>(Arrays.asList(
            "desc", "order", "sort", "sortBy", "column", "field"
    ));

    // AI Provider Settings (for report writing assistance)
    private String activeAIProvider = "ollama";
    private String ollamaEndpoint = "http://localhost:11434";
    private String ollamaModel = "qwen2.5-coder:7b";
    private String openAIKey = "";
    private String openAIBaseUrl = "https://api.openai.com";
    private String openAIModel = "gpt-3.5-turbo";
    private String claudeKey = "";
    private String claudeBaseUrl = "https://api.anthropic.com";
    private String claudeModel = "claude-3-haiku-20240307";
    private int aiMaxTokens = 500;
    private int aiConnectTimeout = 30000;
    private int aiReadTimeout = 60000;

    private Pattern excludedPathPattern = null;
    
    // ── Version Check State ───────────────────────────────────────────────
    private boolean updateAvailable = false;
    private String latestVersion = "";
    private long lastVersionCheckTime = 0;
    private String versionCheckError = null;

    // ── Database Type Selection ───────────────────────────────────────────
    private String selectedDatabaseType = "Generic";  // Generic, MySQL, PostgreSQL, MSSQL, Oracle
    
    public String getSelectedDatabaseType() { return selectedDatabaseType; }
    public void setSelectedDatabaseType(String v) { 
        selectedDatabaseType = v == null ? "Generic" : v; 
    }
    
    public PayloadBuilder.DatabaseType getDatabaseTypeEnum() {
        switch (selectedDatabaseType) {
            case "MySQL": return PayloadBuilder.DatabaseType.MYSQL;
            case "PostgreSQL": return PayloadBuilder.DatabaseType.POSTGRESQL;
            case "MSSQL": return PayloadBuilder.DatabaseType.MSSQL;
            case "Oracle": return PayloadBuilder.DatabaseType.ORACLE;
            default: return PayloadBuilder.DatabaseType.GENERIC;
        }
    }

    // ── Getters / Setters ──────────────────────────────────────────────────

    public boolean isEnableErrorBased() { return enableErrorBased; }
    public void setEnableErrorBased(boolean v) { enableErrorBased = v; }

    public boolean isEnableBooleanBased() { return enableBooleanBased; }
    public void setEnableBooleanBased(boolean v) { enableBooleanBased = v; }

    public boolean isEnableTimeBased() { return enableTimeBased; }
    public void setEnableTimeBased(boolean v) { enableTimeBased = v; }

    public boolean isEnableUnionBased() { return enableUnionBased; }
    public void setEnableUnionBased(boolean v) { enableUnionBased = v; }

    public boolean isScanUrlParams() { return scanUrlParams; }
    public void setScanUrlParams(boolean v) { scanUrlParams = v; }

    public boolean isScanBodyParams() { return scanBodyParams; }
    public void setScanBodyParams(boolean v) { scanBodyParams = v; }

    public boolean isScanHeaders() { return scanHeaders; }
    public void setScanHeaders(boolean v) { scanHeaders = v; }

    public boolean isScanCookies() { return scanCookies; }
    public void setScanCookies(boolean v) { scanCookies = v; }

    public boolean isScanJsonBody() { return scanJsonBody; }
    public void setScanJsonBody(boolean v) { scanJsonBody = v; }

    public boolean isScanXmlBody() { return scanXmlBody; }
    public void setScanXmlBody(boolean v) { scanXmlBody = v; }

    public boolean isTestHiddenParams() { return testHiddenParams; }
    public void setTestHiddenParams(boolean v) { testHiddenParams = v; }

    public int getRequestDelayMs() { return requestDelayMs; }
    public void setRequestDelayMs(int v) { requestDelayMs = Math.max(0, v); }

    public int getTimeoutMs() { return timeoutMs; }
    public void setTimeoutMs(int v) { timeoutMs = Math.max(1000, v); }

    //public int getThreadPoolSize() { return threadPoolSize; }
    //public void setThreadPoolSize(int v) { threadPoolSize = Math.max(1, Math.min(10, v)); }

    public int getMinConfidenceScore() { return minConfidenceScore; }
    public void setMinConfidenceScore(int v) { minConfidenceScore = Math.max(0, Math.min(100, v)); }

    public double getTimingMultiplier() { return timingMultiplier; }
    public void setTimingMultiplier(double v) { timingMultiplier = Math.max(0, v); }

    public int getTimingBaselineSleepSec() { return timingBaselineSleepSec; }
    public void setTimingBaselineSleepSec(int v) { timingBaselineSleepSec = Math.max(2, Math.min(30, v)); }

    // HTTP Method Filtering Getters/Setters
    public boolean isMethodGetEnabled() { return methodGetEnabled; }
    public void setMethodGetEnabled(boolean v) { methodGetEnabled = v; }
    
    public boolean isMethodPostEnabled() { return methodPostEnabled; }
    public void setMethodPostEnabled(boolean v) { methodPostEnabled = v; }
    
    public boolean isMethodPutEnabled() { return methodPutEnabled; }
    public void setMethodPutEnabled(boolean v) { methodPutEnabled = v; }
    
    public boolean isMethodPatchEnabled() { return methodPatchEnabled; }
    public void setMethodPatchEnabled(boolean v) { methodPatchEnabled = v; }
    
    public boolean isMethodDeleteEnabled() { return methodDeleteEnabled; }
    public void setMethodDeleteEnabled(boolean v) { methodDeleteEnabled = v; }
    
    public boolean isExcludeOptions() { return excludeOptions; }
    public void setExcludeOptions(boolean v) { excludeOptions = v; }

    /**
     * Checks if an HTTP method should be scanned based on current filters.
     * @param method HTTP method string (e.g., "GET", "POST")
     * @return true if the method is enabled for scanning
     */
    public boolean isMethodAllowedForScan(String method) {
        if (method == null) return false;
        String upper = method.toUpperCase();
        
        switch (upper) {
            case "GET": return methodGetEnabled;
            case "POST": return methodPostEnabled;
            case "PUT": return methodPutEnabled;
            case "PATCH": return methodPatchEnabled;
            case "DELETE": return methodDeleteEnabled;
            case "OPTIONS": return !excludeOptions;
            default: return false;
        }
    }

    // Traffic Source Filters Getters/Setters
    public boolean isProxyHistoryEnabled() { return proxyHistoryEnabled; }
    public void setProxyHistoryEnabled(boolean v) { proxyHistoryEnabled = v; }
    
    public boolean isScopeFilterEnabled() { return scopeFilterEnabled; }
    public void setScopeFilterEnabled(boolean v) { scopeFilterEnabled = v; }
    
    public boolean isRepeaterEnabled() { return repeaterEnabled; }
    public void setRepeaterEnabled(boolean v) { repeaterEnabled = v; }
    
    // Kill Switch Getters/Setters
    public boolean isKillSwitchEnabled() { return killSwitchEnabled; }
    public void setKillSwitchEnabled(boolean v) { killSwitchEnabled = v; }


    // AI Provider Getters/Setters
    public String getActiveAIProvider() { return activeAIProvider; }
    public void setActiveAIProvider(String v) { activeAIProvider = v; }
    
    public String getOllamaEndpoint() { return ollamaEndpoint; }
    public void setOllamaEndpoint(String v) { ollamaEndpoint = v; }
    
    public String getOllamaModel() { return ollamaModel; }
    public void setOllamaModel(String v) { ollamaModel = v; }
    
    public String getOpenAIKey() { return openAIKey; }
    public void setOpenAIKey(String v) { openAIKey = v; }
    
    public String getOpenAIBaseUrl() { return openAIBaseUrl; }
    public void setOpenAIBaseUrl(String v) { openAIBaseUrl = v; }
    
    public String getOpenAIModel() { return openAIModel; }
    public void setOpenAIModel(String v) { openAIModel = v; }
    
    public String getClaudeKey() { return claudeKey; }
    public void setClaudeKey(String v) { claudeKey = v; }
    
    public String getClaudeBaseUrl() { return claudeBaseUrl; }
    public void setClaudeBaseUrl(String v) { claudeBaseUrl = v; }
    
    public String getClaudeModel() { return claudeModel; }
    public void setClaudeModel(String v) { claudeModel = v; }
    
    public int getAIMaxTokens() { return aiMaxTokens; }
    public void setAIMaxTokens(int v) { aiMaxTokens = v; }
    
    public int getAIConnectTimeout() { return aiConnectTimeout; }
    public void setAIConnectTimeout(int v) { aiConnectTimeout = v; }
    
    public int getAIReadTimeout() { return aiReadTimeout; }
    public void setAIReadTimeout(int v) { aiReadTimeout = v; }

    public List<String> getExcludedParams() { return excludedParams; }
    public List<String> getExcludedPaths() { return excludedPaths; }
    public List<String> getErrorSignatures() { return errorSignatures; }
    public List<String> getHiddenParamNames() { return hiddenParamNames; }

    public String getCustomPayloads() { return customPayloads; }
    public void setCustomPayloads(String v) { customPayloads = v == null ? "" : v; }

    /** Returns all custom payloads as a trimmed list, skipping blanks. */
    public List<String> getParsedCustomPayloads() {
        return Arrays.stream(customPayloads.split("\n"))
                .map(String::trim)
                .filter(s -> !s.isEmpty() && !s.startsWith("#"))
                .collect(java.util.stream.Collectors.toList());
    }

    public boolean isParamExcluded(String paramName) {
        if (paramName == null) return false;
        String lower = paramName.toLowerCase();
        return excludedParams.stream().anyMatch(e -> lower.equals(e.toLowerCase()));
    }

    public boolean isPathExcluded(String url) {
        if (url == null || excludedPaths.isEmpty()) {
            return false;
        }
        
        for (String pattern : excludedPaths) {
            if (isRegexPattern(pattern)) {
                try {
                    Pattern p = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
                    if (p.matcher(url).find()) {
                        return true;
                    }
                } catch (PatternSyntaxException e) {
                    // Invalid regex - treat as plain text fallback
                    if (url.toLowerCase().contains(pattern.toLowerCase())) {
                        return true;
                    }
                }
            } else {
                if (url.toLowerCase().contains(pattern.toLowerCase())) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Extracts the path portion from a full URL (excluding query parameters and fragments)
     * @param url Full URL string
     * @return Path portion, or "/" if extraction fails
     */
    public static String extractPathFromUrl(String url) {
        if (url == null || url.isEmpty()) {
            return "/";
        }
        
        try {
            // Remove protocol and host to find path start
            String withoutProtocol = url;
            int protocolEnd = url.indexOf("://");
            if (protocolEnd != -1) {
                withoutProtocol = url.substring(protocolEnd + 3);
            }
            
            // Find first slash after host (host ends at first / or ? or # or end)
            int pathStart = withoutProtocol.indexOf('/');
            if (pathStart == -1) {
                return "/";
            }
            
            String pathAndQuery = withoutProtocol.substring(pathStart);
            
            // Remove query parameters and fragments
            int queryIndex = pathAndQuery.indexOf('?');
            int fragmentIndex = pathAndQuery.indexOf('#');
            int endIndex = pathAndQuery.length();
            
            if (queryIndex != -1) {
                endIndex = queryIndex;
            }
            if (fragmentIndex != -1 && fragmentIndex < endIndex) {
                endIndex = fragmentIndex;
            }
            
            String path = pathAndQuery.substring(0, endIndex);
            return path.isEmpty() ? "/" : path;
        } catch (Exception e) {
            // Fallback: split on ? and take first part, then find path
            String[] parts = url.split("[?#]");
            String firstPart = parts[0];
            int lastSlash = firstPart.lastIndexOf('/');
            if (lastSlash != -1 && lastSlash < firstPart.length() - 1) {
                // Has path after last slash
                return firstPart;
            }
            return "/";
        }
    }

    /**
     * Determines if a pattern string should be treated as a regular expression
     * @param pattern The pattern string from excluded paths
     * @return true if the pattern contains regex meta-characters
     */
    private static boolean isRegexPattern(String pattern) {
        if (pattern == null || pattern.isEmpty()) {
            return false;
        }
        // Check for common regex meta-characters
        for (char c : pattern.toCharArray()) {
            if (".*+?^${}()|[]\\".indexOf(c) != -1) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if a request's path (excluding query parameters) should be excluded
     * @param url Full request URL
     * @return true if the path matches any exclusion pattern
     */
    public boolean isPathExcludedIgnoreQuery(String url) {
        if (url == null || excludedPaths.isEmpty()) {
            return false;
        }
        
        String path = extractPathFromUrl(url);
        if (path == null || path.isEmpty()) {
            path = "/";
        }
        
        for (String pattern : excludedPaths) {
            if (isRegexPattern(pattern)) {
                try {
                    Pattern p = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
                    if (p.matcher(path).find()) {
                        return true;
                    }
                } catch (PatternSyntaxException e) {
                    if (path.toLowerCase().contains(pattern.toLowerCase())) {
                        return true;
                    }
                }
            } else {
                if (path.toLowerCase().contains(pattern.toLowerCase())) {
                    return true;
                }
            }
        }
        return false;
    }

    public boolean isUseCustomOnly() { return useCustomOnly; }
    public void setUseCustomOnly(boolean v) { useCustomOnly = v; }

    // ── Version Check Getters/Setters ─────────────────────────────────────
    public boolean isUpdateAvailable() { return updateAvailable; }
    public void setUpdateAvailable(boolean v) { updateAvailable = v; }
    
    public String getLatestVersion() { return latestVersion; }
    public void setLatestVersion(String v) { latestVersion = v == null ? "" : v; }
    
    public long getLastVersionCheckTime() { return lastVersionCheckTime; }
    public void setLastVersionCheckTime(long v) { lastVersionCheckTime = v; }
    
    public String getVersionCheckError() { return versionCheckError; }
    public void setVersionCheckError(String v) { versionCheckError = v; }

}
