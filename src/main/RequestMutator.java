package main;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.logging.Logging;
import com.google.gson.*;
import static main.ParameterExtractor.ParamLocation.*;

import java.util.*;
import java.util.regex.*;

/**
 * Injects a payload into a specific parameter within an HttpRequest,
 * handling URL params, body params, JSON (including nested paths), and XML.
 */
public class RequestMutator {

    private final Logging logging;
    private final ScanConfig config;

    // Custom Gson instance that preserves single quotes and other special characters
    private static final Gson GSON_NO_HTML_ESCAPE = new GsonBuilder()
            .disableHtmlEscaping()
            .create();

    public RequestMutator(Logging logging) {
        this.logging = logging;
        this.config = null;
    }

    public RequestMutator(Logging logging, ScanConfig config) {
        this.logging = logging;
        this.config = config;
    }

    /**
     * Returns a modified copy of {@code original} with the given payload
     * injected into {@code param}.
     */
    public HttpRequest inject(HttpRequest original, ParameterExtractor.ExtractedParam param,
                            String payload) {
        // Check if parameter is excluded before injecting
        if (config != null && config.isParamExcluded(param.name)) {
            logging.logToOutput("[RequestMutator] Skipping injection into excluded parameter: " 
                    + param.name + " (location: " + param.location.label + ")");
            return original;
        }
        try {
            switch (param.location) {
                case URL:
                    // Encode spaces as '+' for URL query parameters
                    String urlEncodedPayload = payload.replace(' ', '+');
                    return injectIntoUrlString(original, param.name, urlEncodedPayload);
                case HIDDEN:
                    // Hidden parameters are appended as URL parameters - same encoding
                    String hiddenEncodedPayload = payload.replace(' ', '+');
                    return injectIntoUrlString(original, param.name, hiddenEncodedPayload);
                case BODY:
                    return injectUrlOrBody(original, param, payload, HttpParameterType.BODY);
                case COOKIE:
                    return injectUrlOrBody(original, param, payload, HttpParameterType.COOKIE);
                case JSON:
                case JSON_NESTED:
                    return injectJson(original, param, payload);
                case XML:
                    return injectXml(original, param, payload);
                case HEADER:
                    return injectHeader(original, param, payload);
                default:
                    return original;
            }
        } catch (Exception e) {
            logging.logToOutput("[RequestMutator] Failed to inject into "
                    + param.name + ": " + e.getMessage());
            return original;
        }
    }

    // ── URL / Body / Cookie ───────────────────────────────────────────────

    private HttpRequest injectUrlOrBody(HttpRequest request,
                                        ParameterExtractor.ExtractedParam param,
                                        String payload,
                                        HttpParameterType type) {
        HttpParameter newParam;
        switch (type) {
            case URL:    
                // Encode spaces as '+' for URL query parameters
                // Directly manipulate the URL path+query to preserve literal '+'
                String encodedPayload = payload.replace(' ', '+');
                return injectIntoUrlString(request, param.name, encodedPayload);
            case BODY:   
                newParam = HttpParameter.bodyParameter(param.name, payload); 
                break;
            case COOKIE: 
                newParam = HttpParameter.cookieParameter(param.name, payload); 
                break;
            default:     
                newParam = HttpParameter.urlParameter(param.name, payload); 
                break;
        }

        try {
            return request.withUpdatedParameters(newParam);
        } catch (Exception e) {
            return request.withParameter(newParam);
        }
    }

    /**
     * Directly modifies the URL string to inject a payload into a query parameter,
     * preserving '+' characters as literals.
     * Uses request.withPath() and request.withParameters() to rebuild the request.
     */
    private HttpRequest injectIntoUrlString(HttpRequest request, String paramName, String payload) {
        String fullUrl = request.url();
        
        // Extract the path and existing query string
        String path = extractPath(fullUrl);
        String existingQuery = extractQuery(fullUrl);
        
        // Build new query string with the payload
        String newQuery = buildQueryWithPayload(existingQuery, paramName, payload);
        
        // Rebuild the request
        HttpRequest modified = request.withPath(path);
        if (newQuery != null && !newQuery.isEmpty()) {
            modified = modified.withPath(path + "?" + newQuery);
        }
        
        return modified;
    }

    private String extractPath(String fullUrl) {
        try {
            // Find the path after the host
            int protocolEnd = fullUrl.indexOf("://");
            if (protocolEnd == -1) return "/";
            
            int hostEnd = fullUrl.indexOf("/", protocolEnd + 3);
            if (hostEnd == -1) return "/";
            
            int queryStart = fullUrl.indexOf("?", hostEnd);
            if (queryStart != -1) {
                return fullUrl.substring(hostEnd, queryStart);
            }
            return fullUrl.substring(hostEnd);
        } catch (Exception e) {
            return "/";
        }
    }

    private String extractQuery(String fullUrl) {
        int queryStart = fullUrl.indexOf("?");
        if (queryStart == -1) return null;
        
        int fragmentStart = fullUrl.indexOf("#");
        if (fragmentStart != -1) {
            return fullUrl.substring(queryStart + 1, fragmentStart);
        }
        return fullUrl.substring(queryStart + 1);
    }

    private String buildQueryWithPayload(String existingQuery, String paramName, String payload) {
        // URL-encode the parameter value EXCEPT keep '+' as '+'
        // We need to encode other special characters but leave '+'
        String encodedPayload = encodeQueryParamValue(payload);
        
        if (existingQuery == null || existingQuery.isEmpty()) {
            return paramName + "=" + encodedPayload;
        }
        
        // Check if parameter already exists
        String pattern = "(^|&)" + java.util.regex.Pattern.quote(paramName) + "=[^&]*";
        java.util.regex.Pattern p = java.util.regex.Pattern.compile(pattern);
        java.util.regex.Matcher m = p.matcher(existingQuery);
        
        if (m.find()) {
            // Replace existing parameter
            return m.replaceFirst(m.group(1) + paramName + "=" + encodedPayload);
        } else {
            // Append new parameter
            return existingQuery + "&" + paramName + "=" + encodedPayload;
        }
    }

    /**
     * URL-encode a query parameter value while preserving '+' as literal '+'.
     * Standard URL encoding would convert '+' to '%2B' - we prevent that.
     */
    private String encodeQueryParamValue(String value) {
        StringBuilder result = new StringBuilder();
        for (char c : value.toCharArray()) {
            if (c == '+') {
                result.append('+');  // Keep '+' as literal
            } else if (c == ' ') {
                result.append('+');  // Space becomes '+'
            } else if (c == '&' || c == '=' || c == '?' || c == '#' || c == '%') {
                // Encode these special characters
                result.append(String.format("%%%02X", (int) c));
            } else if (c < 0x20 || c > 0x7E) {
                // Encode non-ASCII characters
                result.append(String.format("%%%02X", (int) c));
            } else {
                result.append(c);
            }
        }
        return result.toString();
    }

    // ── JSON ──────────────────────────────────────────────────────────────

    // Then modify the injectJson method:
    private HttpRequest injectJson(HttpRequest request,
                                    ParameterExtractor.ExtractedParam param,
                                    String payload) {
        String body = request.bodyToString();
        if (body == null || body.isBlank()) return request;

        try {
            JsonElement root = JsonParser.parseString(body);
            // Set the value - using Gson without HTML escaping preserves single quotes
            JsonElement mutated = setJsonValue(root, param.jsonPath, payload);
            String newBody = GSON_NO_HTML_ESCAPE.toJson(mutated);  // ← FIXED: preserves ' as '
            
            // Validate the mutated JSON is still valid
            JsonParser.parseString(newBody);
            
            logging.logToOutput("[RequestMutator] JSON injection successful for " + param.name + ": " + payload);
            return request.withBody(newBody);
        } catch (Exception e) {
            logging.logToOutput("[RequestMutator] JSON injection failed for param " + param.name + ": " + e.getMessage());
            return request;
        }
    }

    /**
     * Recursively traverses a JsonElement by dotted path and sets the leaf value.
     * Supports array indices like "items[0].name".
     */
    private JsonElement setJsonValue(JsonElement root, String path, String value) {
        if (path == null || path.isEmpty()) {
            return new JsonPrimitive(value);
        }

        // Split on first segment
        String[] parts = path.split("\\.", 2);
        String head = parts[0];
        String tail = parts.length > 1 ? parts[1] : "";

        // Handle array index in head, e.g. "items[2]"
        Pattern arrPat = Pattern.compile("^(.+)\\[(\\d+)]$");
        Matcher m = arrPat.matcher(head);

        if (m.matches()) {
            String key = m.group(1);
            int idx = Integer.parseInt(m.group(2));
            JsonObject obj = root.getAsJsonObject();
            JsonArray arr = obj.get(key).getAsJsonArray();
            JsonElement child = setJsonValue(arr.get(idx), tail, value);
            arr.set(idx, child);
            return root;
        }

        if (root.isJsonObject()) {
            JsonObject obj = root.getAsJsonObject();
            if (tail.isEmpty()) {
                obj.addProperty(head, value);
            } else {
                JsonElement child = obj.has(head) ? obj.get(head) : new JsonObject();
                obj.add(head, setJsonValue(child, tail, value));
            }
        }
        return root;
    }

    // ── XML ───────────────────────────────────────────────────────────────

    private HttpRequest injectXml(HttpRequest request,
                                  ParameterExtractor.ExtractedParam param,
                                  String payload) {
        String body = request.bodyToString();
        if (body == null || body.isBlank()) return request;

        // Escape payload for XML context
        String escaped = escapeXml(payload);

        String newBody;
        if (param.jsonPath != null && param.jsonPath.startsWith("@")) {
            // Attribute injection
            String attrName = param.jsonPath.substring(1);
            newBody = body.replaceFirst(
                    "(" + Pattern.quote(attrName) + "=[\"'])[^\"']*([\"'])",
                    "$1" + Matcher.quoteReplacement(escaped) + "$2"
            );
        } else {
            // Tag content injection
            newBody = body.replaceFirst(
                    "(<" + Pattern.quote(param.name) + "(?:\\s[^>]*)?>)[^<]*(</)",
                    "$1" + Matcher.quoteReplacement(escaped) + "$2"
            );
        }

        return request.withBody(newBody);
    }

    // ── Headers ───────────────────────────────────────────────────────────

    private HttpRequest injectHeader(HttpRequest request,
                                     ParameterExtractor.ExtractedParam param,
                                     String payload) {
        return request.withUpdatedHeader(param.name, payload);
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    private String escapeXml(String s) {
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&apos;");
    }
}
