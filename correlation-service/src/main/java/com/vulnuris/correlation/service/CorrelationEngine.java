package com.vulnuris.correlation.service;

import com.vulnuris.correlation.dto.CesEventDto;
import com.vulnuris.correlation.model.EventNode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;

@Slf4j
@Service
@RequiredArgsConstructor
public class CorrelationEngine {

    private final GraphBuilderService graphBuilderService;
    private final AnomalyDetector anomalyDetector;

    public void processEvents(String bundleId, List<CesEventDto> events) {
        log.info("Starting correlation for bundle: {} with {} events", bundleId, events.size());
        
        // Smart processing: filter noise, build graph, enrich
        graphBuilderService.buildGraph(bundleId, events);
        
        // Detect multi-user / anomaly patterns (e.g. Credential Stuffing)
        anomalyDetector.detectAnomalies(events);
        
        log.info("Correlation completed successfully for bundle: {}", bundleId);
    }
}