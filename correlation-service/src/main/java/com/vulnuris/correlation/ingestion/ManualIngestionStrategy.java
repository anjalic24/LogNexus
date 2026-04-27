package com.vulnuris.correlation.ingestion;

import com.vulnuris.correlation.dto.CesEventDto;
import com.vulnuris.correlation.service.CorrelationEngine;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class ManualIngestionStrategy implements IngestionStrategy {
    
    private final CorrelationEngine correlationEngine;

    @Override
    public void process(String bundleId, List<CesEventDto> events) {
        log.info("Invoking manual ingestion strategy for bundleId: {}", bundleId);
        correlationEngine.processEvents(bundleId, events);
    }
}
