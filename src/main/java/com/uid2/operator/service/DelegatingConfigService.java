package com.uid2.operator.service;

import io.vertx.core.json.JsonObject;

import java.util.concurrent.atomic.AtomicReference;

public class DelegatingConfigService implements IConfigService{
    private final AtomicReference<IConfigService> activeConfigService;

    public DelegatingConfigService(IConfigService initialConfigService) {
        this.activeConfigService = new AtomicReference<>(initialConfigService);
    }

    public void updateConfigService(IConfigService newConfigService) {
        this.activeConfigService.set(newConfigService);
    }

    @Override
    public JsonObject getConfig() {
        return activeConfigService.get().getConfig();
    }
}
