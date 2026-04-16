package com.vulnuris.IngestionService.service;

import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

@Service
public class BundleControlService {

    private final Map<String, AtomicBoolean> cancelled = new ConcurrentHashMap<>();

    public void register(String bundleId) {
        cancelled.putIfAbsent(bundleId, new AtomicBoolean(false));
    }

    public boolean cancel(String bundleId) {
        AtomicBoolean flag = cancelled.computeIfAbsent(bundleId, k -> new AtomicBoolean(false));
        return flag.compareAndSet(false, true);
    }

    public boolean isCancelled(String bundleId) {
        AtomicBoolean flag = cancelled.get(bundleId);
        return flag != null && flag.get();
    }

    public void clear(String bundleId) {
        cancelled.remove(bundleId);
    }
}

