package com.vulnuris.IngestionService.service.severity;

import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Set;

@Service
public class WindowsSeverityService {

    private static final Set<String> HIGH_RISK_GROUPS = Set.of(
            "administrators", "domain admins", "enterprise admins"
    );

    private static final Map<Integer, Double> EVENT_ID_FLOORS = Map.of(
            4625, 7.5,
            4720, 8.5,
            4722, 8.0,
            4724, 8.5,
            4732, 9.0,
            4756, 9.0,
            4688, 4.0,
            4672, 9.5,
            1102, 10.0
    );

    public double calculateSeverity(Map<String, Object> record) {

        if (record == null) return 0.0;

        Integer eventId = safeInt(record.get("EventID"));
        String eventType = safeString(record.get("EventType")).toUpperCase();

        Map<String, Object> data =
                (Map<String, Object>) record.getOrDefault("EventData", Map.of());

        String targetUser = safeLower(data.get("TargetUserName"));
        String targetGroup = safeLower(data.get("TargetGroupName"));
        String subjectUser = safeLower(data.get("SubjectUserName"));

        double baseScore = EVENT_ID_FLOORS.getOrDefault(eventId, 3.0);
        double multiplier = 1.0;


        if (eventType.contains("FAIL")) {
            multiplier *= 1.3;
        }


        if (targetGroup != null &&
                (HIGH_RISK_GROUPS.contains(targetGroup) || targetGroup.contains("admin"))) {
            multiplier *= 1.4;
        }


        if (isDifferentUser(subjectUser, targetUser)) {
            multiplier *= 1.2;
        }

        double finalScore = baseScore * multiplier;

        return round(Math.min(finalScore, 10.0));
    }



    private boolean isDifferentUser(String subject, String target) {
        return subject != null && target != null && !subject.equals(target);
    }

    private String safeString(Object obj) {
        return obj != null ? obj.toString() : "";
    }

    private String safeLower(Object obj) {
        return obj != null ? obj.toString().toLowerCase() : null;
    }

    private Integer safeInt(Object obj) {
        try {
            return obj != null ? Integer.parseInt(obj.toString()) : null;
        } catch (Exception e) {
            return null;
        }
    }

    private double round(double value) {
        return Math.round(value * 100.0) / 100.0;
    }

    public String toSeverityLabel(double score) {

        if (score >= 9.0) return "CRITICAL";
        if (score >= 7.0) return "HIGH";
        if (score >= 5.0) return "MEDIUM";
        if (score >= 3.0) return "LOW";
        return "INFO";
    }
}
