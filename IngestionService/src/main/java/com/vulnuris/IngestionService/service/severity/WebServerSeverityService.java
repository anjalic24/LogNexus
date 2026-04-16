package com.vulnuris.IngestionService.service.severity;

import org.springframework.stereotype.Service;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class WebServerSeverityService {

    private static final Pattern LOG_PATTERN = Pattern.compile("^(\\S+) \\S+ \\S+ \\[(.*?)\\] \"(\\S+) (\\S+) \\S+\" (\\d{3}) (\\d+)(?: \"([^\"]*)\" \"([^\"]*)\")?");

    private static final Map<String, Double> SENSITIVE_PATHS = Map.of(
            "/admin", 7.0,
            "/wp-admin", 7.5,
            "/api/v1/auth", 8.0,
            "config", 6.5,
            ".env", 9.0,
            "phpmyadmin", 8.0
    );

    private static final Map<String, Double> SCANNER_AGENTS = Map.of(
            "nikto", 2.0,
            "sqlmap", 3.5,
            "python-requests", 1.5,
            "nmap", 2.0,
            "dirbuster", 2.5
    );

    private static final Map<String, Pattern> ATTACK_SIGNATURES = Map.of(
            "SQLi", Pattern.compile("(?i)(union\\s+select|or\\s+'1'='1'|--|drop\\s+table)"),
            "XSS", Pattern.compile("(?i)(<script>|alert\\(|onerror=)"),
            "Traversal", Pattern.compile("(?i)(\\.\\./|\\.\\.\\\\)"),
            "RCE", Pattern.compile("(?i)(cmd=|/etc/passwd|eval\\(|system\\()"),
            "Log4j", Pattern.compile("(?i)(\\$\\{jndi:)")
    );

    public double calculateSeverity(String rawLog) {
        if (rawLog == null || rawLog.isEmpty()) return 1.0;
        String logLower = rawLog.toLowerCase();

        Matcher matcher = LOG_PATTERN.matcher(rawLog);
        if (!matcher.find()) return 2.0;

        String method = matcher.group(3).toUpperCase();
        String path = matcher.group(4).toLowerCase();
        int statusCode = Integer.parseInt(matcher.group(5));
        String userAgent = matcher.group(8) != null ? matcher.group(8).toLowerCase() : "";

        double baseScore = mapStatusToCes(statusCode);

        double pathFloor = 0.0;
        for (Map.Entry<String, Double> entry : SENSITIVE_PATHS.entrySet()) {
            if (path.contains(entry.getKey())) {
                pathFloor = Math.max(pathFloor, entry.getValue());
            }
        }
        baseScore = Math.max(baseScore, pathFloor);

        double signatureBoost = 0.0;
        for (Pattern pattern : ATTACK_SIGNATURES.values()) {
            if (pattern.matcher(logLower).find()) {
                signatureBoost = 5.0;
                break;
            }
        }

        double multiplier = 1.0;

        if (method.equals("DELETE")) multiplier *= 1.5;
        else if (method.equals("PUT")) multiplier *= 1.3;
        else if (method.equals("POST")) multiplier *= 1.2;

        for (Map.Entry<String, Double> entry : SCANNER_AGENTS.entrySet()) {
            if (userAgent.contains(entry.getKey())) {
                multiplier *= (1 + entry.getValue() / 5);
                break;
            }
        }

        if (userAgent.contains("googlebot") && pathFloor > 0) {
            multiplier *= 1.4;
        }

        double finalScore = (baseScore + signatureBoost) * multiplier;
        return Math.round(Math.min(finalScore, 10.0) * 100.0) / 100.0;
    }

    private double mapStatusToCes(int status) {
        if (status >= 500) return 7.0;
        if (status == 401 || status == 403) return 6.0;
        if (status == 404) return 2.0;
        if (status >= 400) return 4.5;
        return 1.0;
    }

    public String toSeverityLabel(double score) {

        if (score >= 9.0) return "CRITICAL";
        if (score >= 7.0) return "HIGH";
        if (score >= 5.0) return "MEDIUM";
        if (score >= 3.0) return "LOW";
        return "INFO";
    }

}
