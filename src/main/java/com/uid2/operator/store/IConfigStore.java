package com.uid2.operator.store;

import io.vertx.core.json.JsonObject;

public interface IConfigStore {
    RuntimeConfig getConfig();
    void loadContent() throws Exception;
    JsonObject getMetadata() throws Exception;
}
