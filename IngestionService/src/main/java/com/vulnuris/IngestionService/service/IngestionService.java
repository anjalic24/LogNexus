package com.vulnuris.IngestionService.service;

import com.vulnuris.IngestionService.context.IngestionContext;
import com.vulnuris.IngestionService.kafka.KafkaProducerService;
import com.vulnuris.IngestionService.parser.LogParser;
import com.vulnuris.IngestionService.parser.ParserFactory;
import lombok.RequiredArgsConstructor;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.kafka.core.KafkaTemplate;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.List;

@Service
@RequiredArgsConstructor
public class IngestionService {

    private final ParserFactory parserFactory;
    private final KafkaProducerService kafkaProducer;
    private final KafkaTemplate<String, String> bundleSignalKafkaTemplate;
    private final LogStreamService logStreamService;
    private final BundleControlService bundleControlService;

    @Async("ingestionTaskExecutor")
    public void processFilesFromDisk(List<String> filePaths, IngestionContext ingestionContext) {

        try {
            bundleControlService.register(ingestionContext.getBundleId());
            logStreamService.send(ingestionContext.getBundleId(), "📂 Files received");

            for (String path : filePaths) {
                if (bundleControlService.isCancelled(ingestionContext.getBundleId())) {
                    logStreamService.send(ingestionContext.getBundleId(), "🛑 Cancelled by user. Stopping ingestion.");
                    return;
                }

                File file = new File(path);

                logStreamService.send(ingestionContext.getBundleId(), "⚙\uFE0F Processing file: " + file.getName());

                try (InputStream is = new FileInputStream(file)) {

                    logStreamService.send(ingestionContext.getBundleId(), "🔍 Detecting parser...");
                    LogParser parser = parserFactory.getParser(file.getName(), ingestionContext);

                    logStreamService.send(ingestionContext.getBundleId(), "🚀 Parsing started");

                    logStreamService.send(ingestionContext.getBundleId(), "📤 Sending to Kafka");

                    parser.parseStream(is, file.getName())
                            .peek(event -> event.setBundleId(ingestionContext.getBundleId()))
                            .forEach(event -> {
                                if (bundleControlService.isCancelled(ingestionContext.getBundleId())) {
                                    throw new RuntimeException("Cancelled");
                                }
                                kafkaProducer.send(event, ingestionContext);
                            });

                    logStreamService.send(ingestionContext.getBundleId(), "\uD83D\uDC4D Parsing completed: " + file.getName());

                } catch (Exception e) {
                    logStreamService.send(ingestionContext.getBundleId(),
                            "❌ Error processing file: " + file.getName() + " (" + e.getClass().getSimpleName() + ")");
                    throw e;
                }
            }

            if (bundleControlService.isCancelled(ingestionContext.getBundleId())) {
                logStreamService.send(ingestionContext.getBundleId(), "🛑 Cancelled by user. Skipping Kafka bundle completion signal.");
                return;
            }

            bundleSignalKafkaTemplate.send(
                    "bundle-signals",
                    ingestionContext.getBundleId(),
                    ingestionContext.getBundleId()
            );
            logStreamService.send(ingestionContext.getBundleId(), "✅ Kafka publish complete. Correlation will start shortly.");
            logStreamService.send(ingestionContext.getBundleId(), "⏳ Waiting for correlation to persist results...");
        } catch (Exception e) {
            if ("Cancelled".equals(e.getMessage()) || e.getMessage() != null && e.getMessage().toLowerCase().contains("cancel")) {
                logStreamService.send(ingestionContext.getBundleId(), "🛑 Cancelled by user. Ingestion stopped.");
            } else {
                logStreamService.send(ingestionContext.getBundleId(), "❌ Ingestion failed: " + e.getMessage());
            }
        } finally {
            bundleControlService.clear(ingestionContext.getBundleId());
        }
    }


}
