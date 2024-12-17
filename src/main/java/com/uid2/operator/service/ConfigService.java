package com.uid2.operator.service;

import io.vertx.config.ConfigRetriever;
import io.vertx.config.ConfigRetrieverOptions;
import io.vertx.config.ConfigStoreOptions;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;

import static com.uid2.operator.Const.Config.*;

public class ConfigService implements IConfigService {

    private static volatile ConfigService instance;
    private ConfigRetriever configRetriever;


    private ConfigService(Vertx vertx, JsonObject bootstrapConfig) {
        this.initialiseConfigRetriever(vertx, bootstrapConfig);
    }

    public static ConfigService getInstance(Vertx vertx, JsonObject bootstrapConfig) {
        ConfigService configService = instance;

        if (configService == null) {
            synchronized (ConfigService.class) {
                configService = instance;
                if (configService == null) {
                    instance = configService = new ConfigService(vertx, bootstrapConfig);
                }
            }
        }

        return configService;
    }

    @Override
    public JsonObject getConfig() {
        return configRetriever.getCachedConfig();
    }

    private void initialiseConfigRetriever(Vertx vertx, JsonObject bootstrapConfig) {
        String configUrl = bootstrapConfig.getString(CoreConfigUrl);

        ConfigStoreOptions httpStore = new ConfigStoreOptions()
                .setType("http")
                .setConfig(new JsonObject()
                        .put("url", configUrl)
                        .put("method", "GET"));

        ConfigStoreOptions bootstrapStore = new ConfigStoreOptions()
                .setType("json")
                .setConfig(bootstrapConfig);

        ConfigRetrieverOptions retrieverOptions = new ConfigRetrieverOptions()
                .setScanPeriod(bootstrapConfig.getLong(ConfigScanPeriodMs))
                .addStore(bootstrapStore)
                .addStore(httpStore);

        this.configRetriever = ConfigRetriever.create(vertx, retrieverOptions);

        this.configRetriever.getConfig(ar -> {
            if (ar.succeeded()) {
                System.out.println("Successfully loaded config");
            } else {
                System.err.println("Failed to load config: " + ar.cause().getMessage());
            }
        });

    }
}
