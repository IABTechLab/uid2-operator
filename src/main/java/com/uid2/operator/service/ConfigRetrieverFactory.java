package com.uid2.operator.service;

import io.vertx.config.ConfigRetriever;
import io.vertx.config.ConfigRetrieverOptions;
import io.vertx.config.ConfigStoreOptions;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;

import static com.uid2.operator.Const.Config.ConfigScanPeriodMsProp;

public class ConfigRetrieverFactory {
    public ConfigRetriever create(Vertx vertx, JsonObject bootstrapConfig, String operatorKey) {
        String type = bootstrapConfig.getString("type");
        JsonObject storeConfig = bootstrapConfig.getJsonObject("config");
        if (type.equals("http")) {
            storeConfig.put("headers", new JsonObject()
                    .put("Authorization", "Bearer " + operatorKey));
        }

        ConfigStoreOptions storeOptions = new ConfigStoreOptions()
                .setType(type)
                .setConfig(storeConfig);

        ConfigRetrieverOptions retrieverOptions = new ConfigRetrieverOptions()
                .setScanPeriod(bootstrapConfig.getLong(ConfigScanPeriodMsProp))
                .addStore(storeOptions);

        return ConfigRetriever.create(vertx, retrieverOptions);
    }
}
