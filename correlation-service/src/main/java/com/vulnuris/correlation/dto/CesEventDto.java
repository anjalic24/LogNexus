package com.vulnuris.correlation.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

import java.time.Instant;
import java.util.List;
import java.util.Map;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class CesEventDto {
    private String eventId;
    private String bundleId;
    private Instant tsUtc;           
    private String tsOriginal;
    private String tsOffset;
    private String sourceType;
    private String host;
    private String user;
    private String srcIp;
    private Integer srcPort;
    private String dstIp;
    private Integer dstPort;
    private String protocol;
    private String action;
    private String object;
    private String result;
    private double severity;
    private String severityLabel;
    private String message;
    private String userAgent;
    private List<String> iocs;
    private Map<String, String> correlationKeys;
    private Map<String, Object> extra;
    private String wazuhRuleId;
    private Integer wazuhRuleLevel;
    private String windowsEventId;
    private String rawRefFile;
    private Long rawRefOffset;
    private String schemaVersion = "1.0";
}