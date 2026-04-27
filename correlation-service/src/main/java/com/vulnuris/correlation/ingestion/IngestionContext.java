package com.vulnuris.correlation.ingestion;

import com.vulnuris.correlation.dto.CesEventDto;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class IngestionContext {
    
    private final ManualIngestionStrategy manualIngestionStrategy;
    private final KafkaIngestionStrategy kafkaIngestionStrategy;

    public void ingest(String type, String bundleId, List<CesEventDto> events) {
        if ("KAFKA".equalsIgnoreCase(type)) {
            kafkaIngestionStrategy.process(bundleId, events);
        } else {
            manualIngestionStrategy.process(bundleId, events);
        }
    }
}
