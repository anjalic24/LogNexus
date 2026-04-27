package com.vulnuris.IngestionService.kafka;

import com.vulnuris.IngestionService.context.IngestionContext;
import com.vulnuris.IngestionService.model.CesEvent;
import com.vulnuris.IngestionService.service.LogStreamService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class KafkaProducerService {

    private static final String TOPIC_NORMALIZED_EVENTS = "normalized-events";

    private final KafkaTemplate<String, CesEvent> kafkaTemplate;
    private final LogStreamService logStreamService;

    @Autowired
    public KafkaProducerService(
            @Qualifier("cesEventKafkaTemplate") KafkaTemplate<String, CesEvent> kafkaTemplate,
            LogStreamService logStreamService) {
        this.kafkaTemplate = kafkaTemplate;
        this.logStreamService = logStreamService;
    }

    public void send(CesEvent event, IngestionContext ingestionContext) {
        String partitionKey = event.getUser() != null ? event.getUser() : event.getEventId();

        kafkaTemplate
                .send(TOPIC_NORMALIZED_EVENTS, partitionKey, event)
                .whenComplete((result, ex) -> {
                    if (ex != null) {
                        log.error(
                                "[KafkaProducer] Failed to publish event. "
                                + "bundleId={} eventId={} topic={} error={}",
                                ingestionContext.getBundleId(),
                                event.getEventId(),
                                TOPIC_NORMALIZED_EVENTS,
                                ex.getMessage()
                        );
                    } else {
                        log.debug(
                                "[KafkaProducer] Event published. bundleId={} eventId={} "
                                + "partition={} offset={}",
                                ingestionContext.getBundleId(),
                                event.getEventId(),
                                result.getRecordMetadata().partition(),
                                result.getRecordMetadata().offset()
                        );
                    }
                });
    }

    @SuppressWarnings("rawtypes")
    public KafkaTemplate getKafkaTemplate() {
        return kafkaTemplate;
    }
}
