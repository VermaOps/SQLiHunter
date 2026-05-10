package main;

import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.*;
import java.util.regex.*;

/**
 * Analyzes an HTTP response for SQL injection indicators.
 * Produces a scored AnalysisResult with all matched evidence.
 */
public class ResponseAnalyzer {

    public static class AnalysisResult {
        public final boolean isInteresting;
        public final int confidenceScore;       // 0-100
        public final List<String> matchedSignatures;
        public final List<String> evidence;
        public final String primaryType;        // Error / Boolean / Time / Union

        public AnalysisResult(boolean interesting, int score,
                              List<String> sigs, List<String> evidence, String type) {
            this.isInteresting = interesting;
            this.confidenceScore = score;
            this.matchedSignatures = sigs;
            this.evidence = evidence;
            this.primaryType = type;
        }
    }

    private final ScanConfig config;

    public ResponseAnalyzer(ScanConfig config) {
        this.config = config;
    }

    /**
     * Analyze error/boolean response (compare against baseline).
     */
    public AnalysisResult analyzeErrorOrBoolean(
            HttpResponse baseline,
            HttpResponse injected,
            PayloadBuilder.Payload payload) {

        List<String> matched = new ArrayList<>();
        List<String> evidence = new ArrayList<>();
        int score = 0;

        String body = injected != null ? injected.bodyToString() : "";
        String baseBody = baseline != null ? baseline.bodyToString() : "";
        String bodyLower = body != null ? body.toLowerCase() : "";

                // ── Error signature matching ───────────────────────────────────────
        if (payload.type == PayloadBuilder.PayloadType.ERROR_BASED
                || payload.type == PayloadBuilder.PayloadType.CUSTOM) {
            for (String sig : config.getErrorSignatures()) {
                try {
                    Pattern p = Pattern.compile(sig, Pattern.CASE_INSENSITIVE | Pattern.DOTALL);
                    Matcher m = p.matcher(bodyLower);
                    if (m.find()) {
                        // VERIFY: Ensure the matched text actually contains SQL context
                        int matchStart = m.start();
                        int matchEnd = m.end();
                        String matchedText = bodyLower.substring(matchStart, Math.min(matchEnd, matchStart + 100));
                        
                        // Check if the match is in a SQL error context
                        boolean hasSqlContext = false;
                        String[] sqlContextWords = {"line", "column", "position", "near", "at line", 
                                                     "statement", "query", "syntax", "sql", "database",
                                                     "query", "execute", "prepare", "fetch", "row"};
                        for (String ctx : sqlContextWords) {
                            // Check within 50 chars before or after the match
                            int contextStart = Math.max(0, matchStart - 50);
                            int contextEnd = Math.min(body.length(), matchEnd + 50);
                            String contextWindow = bodyLower.substring(contextStart, contextEnd);
                            if (contextWindow.contains(ctx)) {
                                hasSqlContext = true;
                                break;
                            }
                        }
                        
                        // Also check if this looks like a false positive (structured JSON error)
                        boolean isJsonError = false;
                        int jsonStart = Math.max(0, matchStart - 100);
                        int jsonEnd = Math.min(body.length(), matchEnd + 100);
                        String jsonWindow = body.substring(jsonStart, jsonEnd);
                        if (jsonWindow.contains("\"status\"") || jsonWindow.contains("\"error\"") || 
                            jsonWindow.contains("\"code\"") || jsonWindow.contains("\"success\":false")) {
                            // Additional check: if it's a clean API error without SQL indicators
                            if (!hasSqlContext && jsonWindow.matches(".*\\{\\s*\"[^\"]+\"\\s*:\\s*\"?[^\"]*\"?\\s*,?.*")) {
                                isJsonError = true;
                            }
                        }
                        
                        // Only add evidence if it has SQL context OR is not clearly a generic API error
                        if (hasSqlContext || !isJsonError) {
                            matched.add(sig);
                            // Extract a snippet around the match for evidence
                            int start = Math.max(0, matchStart - 40);
                            int end = Math.min(body.length(), matchEnd + 80);
                            String snippet = body.substring(start, end).replaceAll("[\\r\\n]+", " ");
                            // Truncate snippet if too long
                            if (snippet.length() > 200) {
                                snippet = snippet.substring(0, 197) + "...";
                            }
                            evidence.add("SQL error pattern matched: \"" + sig + "\" → ..." + snippet + "...");
                            score += 25;
                        }
                    }
                } catch (PatternSyntaxException ignored) {
                    // Skip malformed patterns
                }
            }
        }

        // ── Boolean differential analysis ─────────────────────────────────
        if (payload.type == PayloadBuilder.PayloadType.BOOLEAN_BASED
                && baseline != null && injected != null) {
            int baseLen = baseBody != null ? baseBody.length() : 0;
            int injLen = body != null ? body.length() : 0;
            int baseStatus = baseline.statusCode();
            int injStatus = injected.statusCode();

            // Status code change
            if (baseStatus != injStatus) {
                evidence.add("Status code changed: " + baseStatus + " → " + injStatus);
                score += 20;
            }

            // Response length differential
            int diff = Math.abs(injLen - baseLen);
            double pct = baseLen > 0 ? (double) diff / baseLen * 100 : 0;
            if (diff > 200 || pct > 15) {
                evidence.add(String.format("Response length changed: %d → %d (Δ%d, %.1f%%)",
                        baseLen, injLen, diff, pct));
                score += (int) Math.min(30, pct);
            }

            // Content difference (keywords appearing/disappearing)
            List<String> keywords = Arrays.asList(
                    "welcome", "login", "error", "invalid", "success",
                    "denied", "unauthorized", "admin", "account");
            for (String kw : keywords) {
                boolean inBase = baseBody != null && baseBody.toLowerCase().contains(kw);
                boolean inInj = body != null && body.toLowerCase().contains(kw);
                if (inBase != inInj) {
                    evidence.add("Keyword '" + kw + "' " + (inInj ? "appeared" : "disappeared"));
                    score += 10;
                }
            }
        }

        // ── Union-based: look for DB version strings in response ───────────
        if (payload.type == PayloadBuilder.PayloadType.UNION_BASED && body != null) {
            List<Pattern> dbVersionPatterns = Arrays.asList(
                    Pattern.compile("\\d+\\.\\d+\\.\\d+-(MySQL|MariaDB)", Pattern.CASE_INSENSITIVE),
                    Pattern.compile("PostgreSQL \\d+\\.\\d+", Pattern.CASE_INSENSITIVE),
                    Pattern.compile("Microsoft SQL Server \\d{4}", Pattern.CASE_INSENSITIVE),
                    Pattern.compile("Oracle Database \\d+", Pattern.CASE_INSENSITIVE),
                    Pattern.compile("SQLite version \\d+\\.\\d+", Pattern.CASE_INSENSITIVE)
            );
            for (Pattern vp : dbVersionPatterns) {
                Matcher vm = vp.matcher(body);
                if (vm.find()) {
                    evidence.add("DB version string in response: " + vm.group());
                    score += 40;
                    matched.add("version_string:" + vm.group());
                }
            }
        }

        // ── Soft heuristics (always applied) ──────────────────────────────
        if (body != null) {
            // Stack trace / exception patterns
            List<String> stackPatterns = Arrays.asList(
                    "at java\\.", "at org\\.", "traceback \\(most recent",
                    "system\\.data\\.sqlclient", "exception in thread",
                    "Caused by:", "NullPointerException", "StackOverflow");
            for (String sp : stackPatterns) {
                if (Pattern.compile(sp, Pattern.CASE_INSENSITIVE).matcher(body).find()) {
                    evidence.add("Stack trace / exception detected");
                    score += 10;
                    break;
                }
            }

            // 500 internal server error
            if (injected != null && injected.statusCode() == 500
                    && (baseline == null || baseline.statusCode() != 500)) {
                evidence.add("Server returned HTTP 500 after injection");
                score += 15;
            }

            // Generic "syntax error" or "query" keywords not in baseline
            List<String> genericSql = Arrays.asList(
                    "syntax error", "invalid query", "query failed",
                    "sql error", "database error", "db error");
            for (String gs : genericSql) {
                if (bodyLower.contains(gs)
                        && (baseBody == null || !baseBody.toLowerCase().contains(gs))) {
                    evidence.add("New SQL keyword in response: '" + gs + "'");
                    score += 12;
                }
            }
        }

        score = Math.min(score, 100);
        boolean interesting = score >= config.getMinConfidenceScore() || !matched.isEmpty();

        String type = payload.type.label;
        return new AnalysisResult(interesting, score, matched, evidence, type);
    }

    /**
     * Analyze time-based response.
     * @param baselineMs  baseline response time in ms
     * @param injectedMs  response time after payload injection in ms
     * @param payload     the time-based payload used
     */
    public AnalysisResult analyzeTimeBased(long baselineMs, long injectedMs,
                                           PayloadBuilder.Payload payload) {
        List<String> evidence = new ArrayList<>();
        int score = 0;

        long expectedMs = (long) payload.expectedSleepSeconds * 1000L;
        long actualDiff = injectedMs - baselineMs;
        double ratio = baselineMs > 0 ? (double) injectedMs / baselineMs : injectedMs;

        evidence.add(String.format("Baseline: %dms | Injected: %dms | Δ: %dms",
                baselineMs, injectedMs, actualDiff));

        // Primary check: actual response time meets or exceeds expected sleep
        if (injectedMs >= expectedMs * 0.8) { // 80% tolerance
            score += 60;
            evidence.add(String.format("Response time (%.1fs) matches expected sleep (%ds)",
                    injectedMs / 1000.0, payload.expectedSleepSeconds));
        }

        // Secondary check: ratio vs baseline
        if (ratio >= config.getTimingMultiplier()) {
            score += 25;
            evidence.add(String.format("Response time is %.1fx baseline (threshold: %.1fx)",
                    ratio, config.getTimingMultiplier()));
        }

        // Sanity: if the server was just generally slow, be conservative
        if (baselineMs > 3000) {
            score = (int) (score * 0.7);
            evidence.add("Note: baseline response was already slow (" + baselineMs + "ms) – confidence reduced");
        }

        score = Math.min(score, 100);
        boolean interesting = score >= config.getMinConfidenceScore();
        return new AnalysisResult(interesting, score, Collections.emptyList(), evidence, "Time-Based");
    }
}
