package com.uid2.operator.service;

import io.vertx.config.ConfigRetriever;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ConfigServiceManager {
    private IConfigService currentConfigService;
    private final ConfigService dynamicConfigService;
    private final StaticConfigService staticConfigService;
    private static final Logger logger = LoggerFactory.getLogger(ConfigServiceManager.class);

    private ConfigServiceManager(ConfigService dynamicConfigService, StaticConfigService staticConfigService, boolean useDynamicConfig) {
        this.dynamicConfigService = dynamicConfigService;
        this.staticConfigService = staticConfigService;
        this.currentConfigService = useDynamicConfig ? dynamicConfigService : staticConfigService;
    }

    public Future<ConfigServiceManager> create(Vertx vertx, JsonObject bootstrapConfig, boolean useDynamicConfig) {
        Promise<ConfigServiceManager> promise = Promise.promise();

        StaticConfigService staticConfigService = new StaticConfigService(bootstrapConfig);

        ConfigRetrieverFactory configRetrieverFactory = new ConfigRetrieverFactory();
        ConfigRetriever configRetriever = configRetrieverFactory.create(vertx, bootstrapConfig);

        ConfigService.create(configRetriever).onComplete(ar -> {
            if (ar.succeeded()) {
                ConfigService dynamicConfigService = ar.result();
                ConfigServiceManager instance = new ConfigServiceManager(dynamicConfigService, staticConfigService, useDynamicConfig);
                promise.complete(instance);
            }
            else {
                promise.fail(ar.cause());
            }
        });

        return promise.future();
    }

    public void updateConfigService(boolean useDynamicConfig) {
        if (useDynamicConfig) {
            logger.info("Switching to DynamicConfigService");
            this.currentConfigService = dynamicConfigService;
        } else {
            logger.info("Switching to StaticConfigService");
            this.currentConfigService = staticConfigService;
        }
    }

    public IConfigService getConfigService() {
        return currentConfigService;
    }
}
