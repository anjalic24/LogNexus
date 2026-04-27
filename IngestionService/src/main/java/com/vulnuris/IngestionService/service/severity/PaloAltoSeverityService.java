package com.vulnuris.IngestionService.service.severity;

import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Set;

@Service
public class PaloAltoSeverityService {

    private static final Set<String> CRITICAL_ZONES =
            Set.of("trust", "dmz", "internal", "prod");

    private static final Set<String> DANGEROUS_APPS =
            Set.of("ssh", "telnet", "rdp", "ftp", "smb", "tftp");

    private static final Map<String, Double> SUBTYPE_FLOORS = Map.of(
            "threat", 8.5,
            "wildfire", 9.0,
            "vulnerability", 9.5,
            "url", 6.0,
            "traffic", 4.0
    );

    public double calculateSeverity(Map<String, Object> record) {

        String type = getString(record, "type");
        String subtype = getString(record, "subtype");
        String action = getString(record, "action");
        String app = getString(record, "app");
        String threatName = getString(record, "threat_name");
        int dport = getInt(record, "dport");

        String dstZone = getString(record, "dst_zone");
        if (dstZone == null) {
            dstZone = getString(record, "to");
        }

        type = toLower(type);
        subtype = toLower(subtype);
        action = toLower(action);
        app = toLower(app);
        dstZone = toLower(dstZone);


        double baseScore = SUBTYPE_FLOORS.getOrDefault(
                subtype,
                SUBTYPE_FLOORS.getOrDefault(type, 3.0)
        );


        if (threatName != null && !threatName.isBlank() &&
                !threatName.equalsIgnoreCase("none")) {
            baseScore = Math.max(baseScore, 9.0);
        }

        double multiplier = 1.0;


        if (dstZone != null && CRITICAL_ZONES.contains(dstZone)) {
            multiplier *= 1.3;
        }


        if ((app != null && DANGEROUS_APPS.contains(app)) ||
                dport == 3389 || dport == 22 || dport == 445) {
            multiplier *= 1.2;
        }


        if ("allow".equals(action) && baseScore >= 6.0) {
            multiplier *= 1.4;
        } else if (action != null &&
                (action.contains("deny") ||
                        action.contains("drop") ||
                        action.contains("block"))) {
            multiplier *= 0.8;
        }

        double finalScore = baseScore * multiplier;

        return Math.round(Math.min(finalScore, 10.0) * 100.0) / 100.0;
    }


    private String getString(Map<String, Object> map, String key) {
        Object val = map.get(key);
        return (val == null) ? null : val.toString();
    }

    private int getInt(Map<String, Object> map, String key) {
        try {
            Object val = map.get(key);
            return (val == null) ? 0 : Integer.parseInt(val.toString());
        } catch (Exception e) {
            return 0;
        }
    }

    private String toLower(String val) {
        return (val == null) ? null : val.toLowerCase();
    }

    public String toSeverityLabel(double score) {

        if (score >= 9.0) return "CRITICAL";
        if (score >= 7.0) return "HIGH";
        if (score >= 5.0) return "MEDIUM";
        if (score >= 3.0) return "LOW";
        return "INFO";
    }
}
