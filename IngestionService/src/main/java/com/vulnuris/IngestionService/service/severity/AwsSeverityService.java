package com.vulnuris.IngestionService.service.severity;

import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Set;

@Service
public class AwsSeverityService {

    private static final Set<String> SCRIPT_TOOLS = Set.of(
            "aws-cli", "boto3", "python", "curl", "postman"
    );

    private static final Map<String, Double> EXACT_MAP = Map.of(
            "authorizesecuritygroupingress", 10.0,
            "putbucketpolicy", 10.0,
            "createaccesskey", 10.0,
            "createloginprofile", 9.5,
            "attachuserpolicy", 9.5,
            "deletetrail", 10.0,
            "stoplogging", 10.0,
            "deletebucket", 9.0,
            "terminateinstances", 8.5,
            "deleteuser", 9.0
    );

    private static final Map<String, Double> SERVICE_FLOORS = Map.of(
            "cloudtrail", 8.5,
            "iam", 7.5,
            "kms", 7.5,
            "sts", 6.5,
            "rds", 6.0,
            "s3", 5.5,
            "ec2", 4.5
    );

    public double calculateSeverity(Map<String, Object> record) {

        String eventName = get(record, "eventName")
                .toLowerCase().replaceAll("[^a-z0-9]+", "");

        if (eventName.isEmpty()) return 1.0;

        String rawSource = get(record, "eventSource").toLowerCase();
        String normalizedSource = rawSource.replace(".amazonaws.com", "");

        Map<String, Object> identity = getMap(record, "userIdentity");

        String userType = get(identity, "type");
        String arn = get(identity, "arn").toLowerCase();

        String userName = get(identity, "userName");

        if (userName.isEmpty()) {
            Map<String, Object> sessionContext = getMap(identity, "sessionContext");
            Map<String, Object> issuer = getMap(sessionContext, "sessionIssuer");
            userName = get(issuer, "userName");
        }

        if (userName.isEmpty() && arn.contains("/")) {
            userName = arn.substring(arn.lastIndexOf("/") + 1);
        }

        String userAgent = get(record, "userAgent").toLowerCase();

        boolean isScript = SCRIPT_TOOLS.stream().anyMatch(userAgent::contains);
        boolean isFailure = !get(record, "errorCode").isEmpty();

        boolean isRoot = userType.equalsIgnoreCase("Root") ||
                userName.equalsIgnoreCase("root") ||
                arn.endsWith(":root");

        double baseScore = EXACT_MAP.getOrDefault(
                eventName,
                SERVICE_FLOORS.getOrDefault(normalizedSource, 3.0)
        );

        double multiplier = 1.0;

        if (isRoot) multiplier *= 1.3;
        if (isFailure) multiplier *= 1.2;
        if (isScript) multiplier *= 1.2;

        double finalScore = baseScore * multiplier;

        return Math.round(Math.min(finalScore, 10.0) * 100.0) / 100.0;
    }

    // Convert numeric score → String severity
    public String toSeverityLabel(double score) {

        if (score >= 9.0) return "CRITICAL";
        if (score >= 7.0) return "HIGH";
        if (score >= 5.0) return "MEDIUM";
        if (score >= 3.0) return "LOW";
        return "INFO";
    }

    private String get(Map<String, Object> map, String key) {
        if (map == null || key == null) return "";
        Object val = map.get(key);
        return val != null ? val.toString() : "";
    }

    private Map<String, Object> getMap(Map<String, Object> map, String key) {
        if (map == null) return Map.of();
        Object val = map.get(key);
        if (val instanceof Map<?, ?>) {
            return (Map<String, Object>) val;
        }
        return Map.of();
    }
}
