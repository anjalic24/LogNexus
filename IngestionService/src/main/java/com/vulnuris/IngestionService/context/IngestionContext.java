package com.vulnuris.IngestionService.context;

import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;

public class IngestionContext {

    private final String bundleId;
    private final Set<String> excludeSourceTypes;

    public IngestionContext(String bundleId) {
        this.bundleId = bundleId;
        this.excludeSourceTypes = Collections.emptySet();
    }

    public IngestionContext(String bundleId, Set<String> excludeSourceTypes) {
        this.bundleId = bundleId;
        this.excludeSourceTypes = (excludeSourceTypes == null)
                ? Collections.emptySet()
                : excludeSourceTypes.stream()
                        .filter(s -> s != null && !s.isBlank())
                        .map(String::toUpperCase)
                        .collect(Collectors.toUnmodifiableSet());
    }

    public String getBundleId() {
        return bundleId;
    }

    public boolean isExcluded(String sourceType) {
        if (excludeSourceTypes.isEmpty() || sourceType == null) return false;
        return excludeSourceTypes.contains(sourceType.toUpperCase());
    }

    public Set<String> getExcludeSourceTypes() {
        return excludeSourceTypes;
    }
}
