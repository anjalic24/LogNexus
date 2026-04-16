package com.vulnuris.IngestionService.model;


import lombok.Builder;
import lombok.Data;

import java.time.Instant;
import java.util.List;
import java.util.Map;

@Data
@Builder
public class CesEvent {

    private String eventId;
    private String bundleId;

    private Instant tsUtc;
    private String tsOriginal;
    private String tsOffset;

    private String sourceType;

    private String host;
    private String user;

    private String srcIp;
    private String dstIp;

    private Integer srcPort;
    private Integer dstPort;

    private String protocol;

    private String action;
    private String object;
    private String result;
    private double severity;
    private String severityLabel;

    private String message;

    private List<String> iocs;

    private Map<String, String> correlationKeys;

    private Map<String, Object> extra;

    private String rawRefFile;
    private Long rawRefOffset;
}
