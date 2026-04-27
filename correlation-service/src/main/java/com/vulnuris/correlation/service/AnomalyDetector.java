package com.vulnuris.correlation.service;

import com.vulnuris.correlation.dto.CesEventDto;
import com.vulnuris.correlation.utils.Constants;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Slf4j
@Service
public class AnomalyDetector {

    public void detectAnomalies(List<CesEventDto> events) {
        Map<String, Long> userCountPerIp = events.stream()
                .filter(e -> e.getSrcIp() != null && e.getUser() != null)
                .collect(Collectors.groupingBy(
                        CesEventDto::getSrcIp,
                        Collectors.mapping(CesEventDto::getUser, Collectors.toSet())
                ))
                .entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey, e -> (long) e.getValue().size()));

        userCountPerIp.forEach((ip, count) -> {
            if (count > Constants.CREDENTIAL_STUFFING_USER_THRESHOLD) {
                log.warn("ANOMALY DETECTED: Credential Stuffing suspected from IP {} with {} distinct users.", ip, count);
            }
        });
    }
}
