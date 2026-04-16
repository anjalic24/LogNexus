package com.vulnuris.IngestionService.service.severity;

import org.springframework.stereotype.Service;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class SyslogSeverityService {

    private static final Pattern PRI_PATTERN = Pattern.compile("^<(\\d+)>");

    private static final Map<String, Double> KEYWORD_BOOSTS = Map.of(
            "failed password", 2.5,
            "firewall rule added", 3.0,
            "accepted publickey", 1.5,
            "invalid user", 2.0,
            "connection refused", 1.5
    );

    private static final Map<String, Double> PROCESS_FLOORS = Map.of(
            "sshd", 5.0,
            "sudo", 6.5,
            "firewalld", 7.0,
            "kernel", 6.0,
            "auth", 5.5
    );

    public double calculateSeverity(String rawLog) {
        if (rawLog == null || rawLog.isEmpty()) return 1.0;
        String logLower = rawLog.toLowerCase();

        int pri = 13;
        Matcher priMatcher = PRI_PATTERN.matcher(rawLog);
        if (priMatcher.find()) {
            pri = Integer.parseInt(priMatcher.group(1));
        }

        int syslogSev = pri % 8;
        double baseScore = mapSyslogLevelToCes(syslogSev);

        double processFloor = 0.0;
        for (Map.Entry<String, Double> entry : PROCESS_FLOORS.entrySet()) {
            if (logLower.contains(entry.getKey())) {
                processFloor = Math.max(processFloor, entry.getValue());
            }
        }
        baseScore = Math.max(baseScore, processFloor);

        double boost = 0.0;
        for (Map.Entry<String, Double> entry : KEYWORD_BOOSTS.entrySet()) {
            if (logLower.contains(entry.getKey())) {
                boost = Math.max(boost, entry.getValue());
            }
        }

        double finalScore = baseScore + boost;
        return Math.round(Math.min(finalScore, 10.0) * 100.0) / 100.0;
    }

    private double mapSyslogLevelToCes(int level) {
        return switch (level) {
            case 0, 1, 2 -> 9.0;
            case 3 -> 7.5;
            case 4 -> 5.5;
            case 5 -> 3.5;
            case 6 -> 2.0;
            default -> 1.0;
        };
    }

    public String toSeverityLabel(double score) {

        if (score >= 9.0) return "CRITICAL";
        if (score >= 7.0) return "HIGH";
        if (score >= 5.0) return "MEDIUM";
        if (score >= 3.0) return "LOW";
        return "INFO";
    }
}

