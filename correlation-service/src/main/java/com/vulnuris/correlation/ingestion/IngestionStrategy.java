package com.vulnuris.correlation.ingestion;

import com.vulnuris.correlation.dto.CesEventDto;

import java.util.List;

public interface IngestionStrategy {
    void process(String bundleId, List<CesEventDto> events);
}
