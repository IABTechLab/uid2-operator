package com.uid2.operator.store;

import io.vertx.core.json.JsonObject;

public class BootstrapConfigStore implements IConfigStore {
    private final JsonObject config;

    public BootstrapConfigStore(JsonObject config) {
        this.config = config;
    }

    @Override
    public JsonObject getConfig() {
        return config;
    }
}
