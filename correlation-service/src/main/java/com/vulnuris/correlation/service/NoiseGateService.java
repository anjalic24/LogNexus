package com.vulnuris.correlation.service;

import com.vulnuris.correlation.dto.CesEventDto;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class NoiseGateService {

    @Value("${correlation.min-severity:4.0}")
    private double minSeverity;

    public boolean isNoise(CesEventDto event) {
        if (event.getSeverity() >= minSeverity) return false;

        if (hasRealIocs(event)) return false;

        if (event.getWazuhRuleLevel() != null && event.getWazuhRuleLevel() >= 8) return false;

        if ("CRITICAL".equalsIgnoreCase(event.getSeverityLabel())) return false;

        if ("HIGH".equalsIgnoreCase(event.getSeverityLabel())) return false;

        if (isHighRiskAction(event.getAction())) return false;

        return true;
    }

    private boolean hasRealIocs(CesEventDto event) {
        if (event.getIocs() == null || event.getIocs().isEmpty()) return false;

        return event.getIocs().stream().anyMatch(ioc -> {
            if (ioc == null || ioc.isBlank()) return false;

            if (ioc.matches("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$")) return false;

            if (ioc.contains("@")) return false;

            if (ioc.startsWith("/api/") || ioc.startsWith("/static/")) return false;

            if (ioc.endsWith(".onmicrosoft.com")) return false;
            return true;
        });
    }

    private boolean isHighRiskAction(String action) {
        if (action == null) return false;
        String upper = action.toUpperCase();
        return switch (upper) {
            case "SQL_INJECTION", "RCE_ATTACK", "LFI_ATTACK", "COMMAND_INJECTION",
                 "FILE_UPLOAD_ATTACK", "DATA_EXFILTRATION", "DNS_TUNNELING",
                 "PRIV_ESC", "RDP_HIJACK", "PERSISTENCE", "USER_CREATE",
                 "PASSWORD_RESET", "REMOTE_EXEC", "GPO_CHANGE",
                 "MALWARE DETECTED." -> true;
            default -> false;
        };
    }
}