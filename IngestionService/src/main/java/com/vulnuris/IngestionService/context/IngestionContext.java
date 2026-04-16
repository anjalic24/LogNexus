package com.vulnuris.IngestionService.context;

public class IngestionContext {

    private final String bundleId;

    public IngestionContext(String bundleId) {
        this.bundleId = bundleId;
    }

    public String getBundleId() {
        return bundleId;
    }

}
