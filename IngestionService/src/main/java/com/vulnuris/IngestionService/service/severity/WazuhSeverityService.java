package com.vulnuris.IngestionService.service.severity;

import org.springframework.stereotype.Service;

import java.util.*;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.Map;
import java.util.Set;

@Service
public class WazuhSeverityService {

    private static final Set<String> ATTACK_GROUPS = Set.of("attack", "sql_injection", "trojan", "malware", "rootcheck", "authentication_failures");
    private static final Set<String> PRIV_GROUPS = Set.of("sudo", "account_changed", "privilege_escalation");
    private static final Set<String> CRITICAL_HOSTS = Set.of("win-dc-01", "db-server-01", "firewall-01");

    private static final Map<String, Double> SIGNATURE_OVERRIDES = Map.of(
            "31106", 10.0,
            "550", 9.5,
            "92100", 9.0,
            "510", 8.5,
            "5712", 8.5,
            "5710", 7.0
    );

    public double calculateSeverity(JsonNode record) {
        JsonNode ruleNode = record.path("rule");
        int wazuhLevel = ruleNode.path("level").asInt(0);
        String ruleId = ruleNode.path("id").asText("");
        String agentName = record.path("agent").path("name").asText("").toLowerCase();

        double baseScore = SIGNATURE_OVERRIDES.getOrDefault(ruleId, getBaseScore(wazuhLevel));

        double contextMult = 1.0;
        JsonNode groups = ruleNode.path("groups");

        if (groups.isArray()) {
            for (JsonNode group : groups) {
                String g = group.asText().toLowerCase();
                if (ATTACK_GROUPS.contains(g)) contextMult = Math.max(contextMult, 1.3);
                if (PRIV_GROUPS.contains(g)) contextMult = Math.max(contextMult, 1.2);
            }
        }

        double assetMult = 1.0;
        if (!agentName.isEmpty()) {
            for (String host : CRITICAL_HOSTS) {
                if (agentName.contains(host)) {
                    assetMult = 1.3;
                    break;
                }
            }
        }

        double finalScore = baseScore * contextMult * assetMult;

        return Math.round(Math.min(finalScore, 10.0) * 100.0) / 100.0;
    }

    private double getBaseScore(int level) {
        if (level >= 12) return 9.0;
        if (level >= 10) return 7.5;
        if (level >= 7)  return 5.5;
        if (level >= 3)  return 3.0;
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