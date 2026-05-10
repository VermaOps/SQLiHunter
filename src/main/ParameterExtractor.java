package main;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.logging.Logging;
import com.google.gson.*;

import java.util.*;
import java.util.regex.*;
import java.util.regex.Pattern;
import java.util.regex.Matcher;


/**
 * Extracts all injectable parameters from an HTTP request.
 * Handles URL params, body params, JSON (including nested), XML, headers, and cookies.
 * Also supports hidden parameter discovery via common name heuristics.
 */
public class ParameterExtractor {

    public enum ParamLocation {
        URL("URL"),
        BODY("Body"),
        JSON("JSON"),
        JSON_NESTED("JSON (nested)"),
        XML("XML"),
        HEADER("Header"),
        COOKIE("Cookie"),
        HIDDEN("Hidden (discovered)");

        public final String label;
        ParamLocation(String label) { this.label = label; }
    }

    public static class ExtractedParam {
        public final String name;
        public final String originalValue;
        public final ParamLocation location;
        public final String jsonPath;        // for JSON params, e.g. "user.address.zip"
        public final int bodyOffset;         // byte offset in body for precise replacement
        public final HttpParameterType burpType;

        public ExtractedParam(String name, String value, ParamLocation loc,
                              String jsonPath, HttpParameterType burpType) {
            this.name = name;
            this.originalValue = value;
            this.location = loc;
            this.jsonPath = jsonPath;
            this.bodyOffset = -1;
            this.burpType = burpType;
        }

        @Override
        public String toString() {
            return location.label + " → " + name + " = \"" + originalValue + "\""
                    + (jsonPath != null ? " (path: " + jsonPath + ")" : "");
        }
    }

    private final ScanConfig config;
    private final Logging logging;

    public ParameterExtractor(ScanConfig config, Logging logging) {
        this.config = config;
        this.logging = logging;
    }

    /**
     * Extract all injectable parameters from the request.
     */
    public List<ExtractedParam> extract(HttpRequest request) {
        List<ExtractedParam> params = new ArrayList<>();
        Set<String> seen = new HashSet<>();

        String contentType = getHeader(request, "Content-Type");
        boolean isJson = contentType != null && contentType.toLowerCase().contains("json");
        boolean isXml = contentType != null
                && (contentType.toLowerCase().contains("xml")
                || contentType.toLowerCase().contains("text/plain"));
        String body = request.bodyToString();

        // URL / query parameters
        if (config.isScanUrlParams()) {
            for (HttpParameter p : request.parameters()) {
                if (p.type() == HttpParameterType.URL && !config.isParamExcluded(p.name())) {
                    if (seen.add("url:" + p.name())) {
                        params.add(new ExtractedParam(p.name(), p.value(),
                                ParamLocation.URL, null, HttpParameterType.URL));
                    }
                }
            }
        }

        // Body parameters (form-encoded)
        if (config.isScanBodyParams() && !isJson && !isXml) {
            for (HttpParameter p : request.parameters()) {
                if (p.type() == HttpParameterType.BODY && !config.isParamExcluded(p.name())) {
                    if (seen.add("body:" + p.name())) {
                        params.add(new ExtractedParam(p.name(), p.value(),
                                ParamLocation.BODY, null, HttpParameterType.BODY));
                    }
                }
            }
        }

        // JSON body
        if (config.isScanJsonBody() && isJson && body != null && !body.isBlank()) {
            extractJsonParams(body, params, seen);
        }

        // XML body
        if (config.isScanXmlBody() && isXml && body != null && !body.isBlank()) {
            extractXmlParams(body, params, seen);
        }

        // Headers
        if (config.isScanHeaders()) {
            List<String> interestingHeaders = Arrays.asList(
                    "Origin", "X-Forwarded-For", "X-Real-IP", "X-Custom-IP-Authorization",
                    "Referer", "User-Agent", "X-Api-Version", "X-Request-ID"
            );
            for (String hdr : interestingHeaders) {
                String val = getHeader(request, hdr);
                if (val != null && !config.isParamExcluded(hdr) && seen.add("hdr:" + hdr)) {
                    params.add(new ExtractedParam(hdr, val,
                            ParamLocation.HEADER, null, null));
                }
            }
        }

        // Cookies
        if (config.isScanCookies()) {
            for (HttpParameter p : request.parameters()) {
                if (p.type() == HttpParameterType.COOKIE && !config.isParamExcluded(p.name())) {
                    if (seen.add("cookie:" + p.name())) {
                        params.add(new ExtractedParam(p.name(), p.value(),
                                ParamLocation.COOKIE, null, HttpParameterType.COOKIE));
                    }
                }
            }
        }

        // Hidden / undiscovered params
        if (config.isTestHiddenParams()) {
            String path = request.path().split("\\?")[0];
            for (String name : config.getHiddenParamNames()) {
                if (!seen.contains("url:" + name)
                        && !seen.contains("body:" + name)
                        && !config.isParamExcluded(name)) {
                    // Only probe if not already found
                    params.add(new ExtractedParam(name, "1",
                            ParamLocation.HIDDEN, null, HttpParameterType.URL));
                }
            }
        }

        logging.logToOutput("[ParameterExtractor] Found " + params.size()
                + " params in " + request.method() + " " + request.path());
        return params;
    }

    // ── JSON extraction (recursive, handles nested objects & arrays) ──────

    private void extractJsonParams(String json, List<ExtractedParam> out, Set<String> seen) {
        try {
            JsonElement root = JsonParser.parseString(json);
            extractJsonElement(root, "", out, seen);
        } catch (JsonSyntaxException e) {
            logging.logToOutput("[ParameterExtractor] JSON parse failed: " + e.getMessage());
        }
    }

    private void extractJsonElement(JsonElement el, String path,
                                    List<ExtractedParam> out, Set<String> seen) {
        if (el.isJsonObject()) {
            for (Map.Entry<String, JsonElement> entry : el.getAsJsonObject().entrySet()) {
                String childPath = path.isEmpty() ? entry.getKey() : path + "." + entry.getKey();
                JsonElement child = entry.getValue();
                if (child.isJsonPrimitive()) {
                    // Leaf node — injectable
                    String name = entry.getKey();
                    String value = child.getAsString();
                    if (!config.isParamExcluded(name) && seen.add("json:" + childPath)) {
                        ParamLocation loc = path.isEmpty()
                                ? ParamLocation.JSON : ParamLocation.JSON_NESTED;
                        out.add(new ExtractedParam(name, value, loc, childPath, null));
                    }
                } else {
                    // Recurse into objects / arrays
                    extractJsonElement(child, childPath, out, seen);
                }
            }
        } else if (el.isJsonArray()) {
            JsonArray arr = el.getAsJsonArray();
            for (int i = 0; i < arr.size(); i++) {
                extractJsonElement(arr.get(i), path + "[" + i + "]", out, seen);
            }
        }
    }

    // ── XML extraction (tag text content) ────────────────────────────────

    private void extractXmlParams(String xml, List<ExtractedParam> out, Set<String> seen) {
        // Simple regex-based extraction; avoids heavyweight XML parser dependency
        Pattern tagPattern = Pattern.compile(
                "<([a-zA-Z][a-zA-Z0-9_\\-]*)(?:\\s[^>]*)?>([^<]+)</\\1>",
                Pattern.DOTALL);
        Matcher m = tagPattern.matcher(xml);
        while (m.find()) {
            String tagName = m.group(1);
            String tagValue = m.group(2).trim();
            if (!tagValue.isEmpty()
                    && !config.isParamExcluded(tagName)
                    && seen.add("xml:" + tagName)) {
                out.add(new ExtractedParam(tagName, tagValue,
                        ParamLocation.XML, null, null));
            }
        }

        // Also extract attributes
        Pattern attrPattern = Pattern.compile(
                "\\s([a-zA-Z][a-zA-Z0-9_\\-]*)=[\"']([^\"']+)[\"']");
        m = attrPattern.matcher(xml);
        while (m.find()) {
            String name = m.group(1);
            String value = m.group(2);
            if (!config.isParamExcluded(name) && seen.add("xmlattr:" + name)) {
                out.add(new ExtractedParam(name, value, ParamLocation.XML, "@" + name, null));
            }
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    private String getHeader(HttpRequest request, String name) {
        return request.headers().stream()
                .filter(h -> h.name().equalsIgnoreCase(name))
                .map(h -> h.value())
                .findFirst()
                .orElse(null);
    }
}
