package com.uid2.operator.service;

import io.vertx.core.json.JsonObject;


public class StaticConfigService implements IConfigService {
    private final JsonObject staticConfig;

    public StaticConfigService(JsonObject staticConfig) {
        this.staticConfig = staticConfig;
    }

    @Override
    public JsonObject getConfig() {
        return staticConfig;
    }
}
