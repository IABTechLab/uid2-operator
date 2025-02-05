package com.uid2.operator.service;

import io.vertx.config.ConfigRetriever;
import io.vertx.config.ConfigRetrieverOptions;
import io.vertx.config.ConfigStoreOptions;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import static com.uid2.operator.Const.Config.ConfigScanPeriodMsProp;

public class ConfigRetrieverFactory {
    private static final Logger LOGGER = LoggerFactory.getLogger(ConfigRetrieverFactory.class);
    public static ConfigRetriever create(Vertx vertx, JsonObject bootstrapConfig, String operatorKey) {
        String type = bootstrapConfig.getString("type");
        JsonObject storeConfig = bootstrapConfig.getJsonObject("config");
        LOGGER.info("ABU operatorKey");
        LOGGER.info(operatorKey);
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
