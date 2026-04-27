package com.vulnuris.correlation.dto;

import lombok.Data;
import java.util.List;

@Data
public class FilteredIngestRequest {
    private List<CesEventDto> events;
    private String minSeverity;   // LOW, MEDIUM, HIGH, CRITICAL
    private Double timeFrom;      // Unix timestamp (seconds)
    private Double timeTo;        // Unix timestamp (seconds)
}
