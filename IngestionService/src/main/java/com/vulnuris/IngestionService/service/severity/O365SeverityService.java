package com.vulnuris.IngestionService.service.severity;

import org.springframework.stereotype.Service;

import java.util.*;

@Service
public class O365SeverityService {

    private static final String CORP_DOMAIN = "@contoso.com";

    private static final Set<String> SCRIPT_TOOLS =
            Set.of("python", "curl", "postman", "powershell", "java");

    private static final Map<String, Double> EXACT_MAP = Map.of(
            "newinboxrule", 10.0,
            "addrolegroupmember", 10.0,
            "userloginfailed", 8.5,
            "filedeleted", 7.0,
            "mailitemsaccessed", 6.5,
            "filedownloaded", 6.5
    );

    private static final Map<String, Double> WORKLOAD_FLOORS = Map.of(
            "azureactivedirectory", 5.0,
            "exchange", 5.5,
            "sharepoint", 5.0,
            "onedrive", 5.0,
            "securitycompliance", 8.5,
            "microsoftteams", 4.5
    );

    public double calculateSeverity(Map<String, Object> record) {

        if (record == null || record.isEmpty()) return 1.0;

        // -------- Operation --------
        String operation = normalize(getString(record, "Operation"));
        if (operation.isEmpty()) return 1.0;

        // -------- Workload --------
        String workload = normalize(getString(record, "Workload"));

        // -------- User --------
        String userId = normalize(getString(record, "UserId"));

        if (userId.isEmpty()) {
            Object actorObj = record.get("Actor");
            if (actorObj instanceof Map<?, ?> actor) {
                userId = normalize(getString(actor, "ID"));
            }
        }

        // -------- Result --------
        String resultStatus = normalize(getString(record, "ResultStatus"));

        // -------- UserType --------
        int userType = getInt(record.get("UserType"));

        // -------- UserAgent --------
        String userAgent = normalize(getString(record, "userAgent"));

        if (userAgent.isEmpty()) {
            userAgent = extractUserAgentFromExtended(record.get("ExtendedProperties"));
        }

        // -------- Flags --------
        boolean isExternal = userId.contains("@") && !userId.endsWith(CORP_DOMAIN);
        boolean isScript = SCRIPT_TOOLS.stream().anyMatch(userAgent::contains);
        boolean isFailure = resultStatus.contains("fail") || resultStatus.contains("error");

        // -------- Base Score --------
        double baseScore = EXACT_MAP.getOrDefault(
                operation,
                WORKLOAD_FLOORS.getOrDefault(workload, 3.0)
        );

        // -------- Context Boost --------
        if (isExternal && isFailure && isScript) {
            baseScore = Math.max(baseScore, 9.5);
        } else if (isExternal && (isFailure || isScript)) {
            baseScore = Math.max(baseScore, 8.5);
        }

        if (operation.contains("download") && isExternal) {
            baseScore = Math.max(baseScore, 8.5);
        }

        // -------- Multipliers --------
        double multiplier = 1.0;

        if (userType == 2 && baseScore >= 6.0) multiplier *= 1.3;
        if (isScript) multiplier *= 1.4;
        if (isExternal) multiplier *= 1.4;
        if (isFailure) multiplier *= 1.2;

        double finalScore = baseScore * multiplier;

        return Math.round(Math.min(finalScore, 10.0) * 100.0) / 100.0;
    }

    // ================= HELPERS =================

    private String getString(Map<?, ?> map, String key) {
        if (map == null || key == null) return "";
        Object val = map.get(key);
        return val == null ? "" : val.toString();
    }

    private int getInt(Object val) {
        if (val == null) return 0;
        try {
            if (val instanceof Number) {
                return ((Number) val).intValue();
            }
            return Integer.parseInt(val.toString());
        } catch (Exception e) {
            return 0;
        }
    }

    private String normalize(String input) {
        if (input == null) return "";
        return input.trim()
                .toLowerCase()
                .replaceAll("[\\s_-]+", "");
    }

    private String extractUserAgentFromExtended(Object extObj) {

        if (!(extObj instanceof List<?> list)) return "";

        for (Object item : list) {
            if (item instanceof Map<?, ?> entry) {

                Object name = entry.get("Name");
                Object value = entry.get("Value");

                if (name != null &&
                        "UserAgent".equalsIgnoreCase(name.toString()) &&
                        value != null) {

                    return value.toString().toLowerCase();
                }
            }
        }

        return "";
    }

    public String toSeverityLabel(double score) {

        if (score >= 9.0) return "CRITICAL";
        if (score >= 7.0) return "HIGH";
        if (score >= 5.0) return "MEDIUM";
        if (score >= 3.0) return "LOW";
        return "INFO";
    }
}
