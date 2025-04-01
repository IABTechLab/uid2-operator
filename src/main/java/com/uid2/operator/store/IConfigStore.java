package com.uid2.operator.store;

import io.vertx.core.json.JsonObject;

public interface IConfigStore {
    JsonObject getConfig();
}
