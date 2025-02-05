package com.uid2.operator.service;

import io.vertx.config.ConfigRetriever;
import io.vertx.config.ConfigRetrieverOptions;
import io.vertx.config.ConfigStoreOptions;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;

import static com.uid2.operator.Const.Config.ConfigScanPeriodMsProp;

public class ConfigRetrieverFactory {
    public static ConfigRetriever create(Vertx vertx, JsonObject bootstrapConfig, String operatorKey) {
        String type = bootstrapConfig.getString("type");
        JsonObject storeConfig = bootstrapConfig.getJsonObject("config");
        LOGGER.info("ABU operatorKey");
        LOGGER.info(operatorKey);
        if (type.equals("http")) {
            LOGGER.info("ABU httpcall");
            storeConfig.put("headers", new JsonObject()
                    .put("Authorization", "Bearer " + operatorKey));
            LOGGER.info("ABU header uodated");
        }

        ConfigStoreOptions storeOptions = new ConfigStoreOptions()
                .setType(type)
                .setConfig(storeConfig);

        LOGGER.info("ABU storeOptions uodated");

        ConfigRetrieverOptions retrieverOptions = new ConfigRetrieverOptions()
                .setScanPeriod(bootstrapConfig.getLong(ConfigScanPeriodMsProp))
                .addStore(storeOptions);

        LOGGER.info("ABU retrieverOptions uodated");

        return ConfigRetriever.create(vertx, retrieverOptions);
    }
}
