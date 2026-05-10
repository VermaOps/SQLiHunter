package main;

public class VersionManager {
    
    public static String getCurrentVersion() {
        return SQLiHunterExtension.VERSION;
    }
    
    public static int compareVersions(String v1, String v2) {
        if (v1 == null && v2 == null) return 0;
        if (v1 == null) return -1;
        if (v2 == null) return 1;
        
        String[] parts1 = v1.replaceFirst("^v", "").split("[-.]");
        String[] parts2 = v2.replaceFirst("^v", "").split("[-.]");
        
        int maxLen = Math.max(parts1.length, parts2.length);
        for (int i = 0; i < maxLen; i++) {
            int num1 = (i < parts1.length && isNumeric(parts1[i])) ? Integer.parseInt(parts1[i]) : 0;
            int num2 = (i < parts2.length && isNumeric(parts2[i])) ? Integer.parseInt(parts2[i]) : 0;
            if (num1 != num2) return num1 - num2;
        }
        return 0;
    }
    
    private static boolean isNumeric(String s) {
        if (s == null || s.isEmpty()) return false;
        for (char c : s.toCharArray()) {
            if (!Character.isDigit(c)) return false;
        }
        return true;
    }
    
    public static String extractTagName(String json) {
        String search = "\"tag_name\":\"";
        int start = json.indexOf(search);
        if (start == -1) return null;
        start += search.length();
        int end = json.indexOf("\"", start);
        if (end == -1) return null;
        return json.substring(start, end);
    }
}