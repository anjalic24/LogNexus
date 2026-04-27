package com.vulnuris.correlation.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Duration;

@Slf4j
@Component
public class ThreatIntelCacheLoader {

    private final RedisTemplate<String, Object> redisTemplate;

    @Value("${correlation.cisa-kev-url:https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json}")
    private String cisaKevUrl;

    private final WebClient webClient = WebClient.builder()
            .codecs(configurer -> configurer.defaultCodecs().maxInMemorySize(5 * 1024 * 1024))
            .build();

    private final ObjectMapper objectMapper = new ObjectMapper();

    public ThreatIntelCacheLoader(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @PostConstruct
    public void loadOnStartup() {
        log.info("Loading threat intelligence caches...");

        loadCisaKevCache();

        log.info("Threat intelligence cache loading complete.");
    }

    private void loadCisaKevCache() {
        try {
            String cacheKey = "cisa_kev:loaded";
            if (Boolean.TRUE.equals(redisTemplate.hasKey(cacheKey))) {
                log.info("CISA KEV cache already loaded, skipping.");
                return;
            }

            log.info("Fetching CISA KEV catalog...");
            String response = webClient.get()
                    .uri(cisaKevUrl)
                    .retrieve()
                    .bodyToMono(String.class)
                    .block(Duration.ofSeconds(30));

            JsonNode root = objectMapper.readTree(response);
            JsonNode vulnerabilities = root.path("vulnerabilities");

            int count = 0;
            if (vulnerabilities.isArray()) {
                for (JsonNode vuln : vulnerabilities) {
                    String cveId = vuln.path("cveID").asText("");
                    String vendorProject = vuln.path("vendorProject").asText("");
                    String product = vuln.path("product").asText("");
                    String knownRansomware = vuln.path("knownRansomwareCampaignUse").asText("Unknown");

                    if (!cveId.isEmpty()) {
                        String kevKey = "cisa_kev:cve:" + cveId;
                        String value = vendorProject + "|" + product + "|" + knownRansomware;
                        redisTemplate.opsForValue().set(kevKey, value, Duration.ofHours(24));
                        count++;
                    }
                }
            }

            redisTemplate.opsForValue().set(cacheKey, "true", Duration.ofHours(12));
            log.info("CISA KEV catalog loaded: {} CVEs cached in Redis.", count);

        } catch (Exception e) {
            log.warn("Failed to load CISA KEV catalog (non-fatal, will retry on next restart): {}", e.getMessage());
        }
    }
}