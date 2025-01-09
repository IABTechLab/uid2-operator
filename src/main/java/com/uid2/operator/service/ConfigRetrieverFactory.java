package com.uid2.operator.service;

import com.uid2.operator.Const;
import io.vertx.config.ConfigRetriever;
import io.vertx.config.ConfigRetrieverOptions;
import io.vertx.config.ConfigStoreOptions;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;

import static com.uid2.operator.Const.Config.ConfigScanPeriodMs;
import static com.uid2.operator.Const.Config.CoreConfigPath;

public class ConfigRetrieverFactory {
    public ConfigRetriever create(Vertx vertx, JsonObject bootstrapConfig) {
        String configPath = bootstrapConfig.getString(CoreConfigPath);


        ConfigStoreOptions httpStore = new ConfigStoreOptions()
                .setType("http")
                .setOptional(true)
                .setConfig(new JsonObject()
                        .put("host", "127.0.0.1")
                        .put("port", Const.Port.ServicePortForCore)
                        .put("path", configPath));

        ConfigRetrieverOptions retrieverOptions = new ConfigRetrieverOptions()
                .setScanPeriod(bootstrapConfig.getLong(ConfigScanPeriodMs))
                .addStore(httpStore);

        return ConfigRetriever.create(vertx, retrieverOptions);
    }
}
