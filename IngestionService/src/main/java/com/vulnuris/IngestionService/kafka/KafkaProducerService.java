package com.vulnuris.IngestionService.kafka;

import com.vulnuris.IngestionService.context.IngestionContext;
import com.vulnuris.IngestionService.model.CesEvent;
import com.vulnuris.IngestionService.service.LogStreamService;
import lombok.RequiredArgsConstructor;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

//@Service
//@RequiredArgsConstructor
//public class KafkaProducerService {
//
//    private final KafkaTemplate<String, CesEvent> kafkaTemplate;
//
//    public void send(CesEvent event) {
//        kafkaTemplate.send("normalized-events", event.getUser(), event);
//    }
//}

@Service
@RequiredArgsConstructor
public class KafkaProducerService {

    private final KafkaTemplate<String, CesEvent> kafkaTemplate;
    private final LogStreamService logStreamService;

    public void send(CesEvent event, IngestionContext ingestionContext) {
        try {
            kafkaTemplate
                    .send("normalized-events", event.getUser(), event)
                    .get();

        } catch (Exception e) {
            throw new RuntimeException("Kafka publish failed", e);
        }
    }

    @SuppressWarnings("rawtypes")
    public KafkaTemplate getKafkaTemplate() {
        return kafkaTemplate;
    }
}
