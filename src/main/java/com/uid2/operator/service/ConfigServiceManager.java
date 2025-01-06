package com.uid2.operator.service;

import com.uid2.operator.Const;
import io.vertx.config.ConfigRetriever;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ConfigServiceManager {
    private final DelegatingConfigService delegatingConfigService;
    private final ConfigService dynamicConfigService;
    private final StaticConfigService staticConfigService;
    private static final Logger logger = LoggerFactory.getLogger(ConfigServiceManager.class);

    private ConfigServiceManager(ConfigService dynamicConfigService, StaticConfigService staticConfigService, boolean useDynamicConfig) {
        this.dynamicConfigService = dynamicConfigService;
        this.staticConfigService = staticConfigService;
        this.delegatingConfigService = new DelegatingConfigService(useDynamicConfig ? dynamicConfigService : staticConfigService);
    }

    public static Future<ConfigServiceManager> create(Vertx vertx, JsonObject bootstrapConfig, boolean useDynamicConfig) {
        Promise<ConfigServiceManager> promise = Promise.promise();

        StaticConfigService staticConfigService = new StaticConfigService(bootstrapConfig);

        ConfigRetrieverFactory configRetrieverFactory = new ConfigRetrieverFactory();
        ConfigRetriever configRetriever = configRetrieverFactory.create(vertx, bootstrapConfig);

        ConfigService.create(configRetriever).onComplete(ar -> {
            if (ar.succeeded()) {
                ConfigService dynamicConfigService = ar.result();
                ConfigServiceManager instance = new ConfigServiceManager(dynamicConfigService, staticConfigService, useDynamicConfig);
                instance.initialiseListener(vertx);
                promise.complete(instance);
            }
            else {
                promise.fail(ar.cause());
            }
        });

        return promise.future();
    }

    private void initialiseListener(Vertx vertx) {
        vertx.eventBus().consumer(Const.Config.RemoteConfigFlagEventBus, message -> {
           boolean useDynamicConfig = Boolean.parseBoolean(message.body().toString());

           this.updateConfigService(useDynamicConfig);
        });
    }

    public void updateConfigService(boolean useDynamicConfig) {
        if (useDynamicConfig) {
            logger.info("Switching to DynamicConfigService");
            this.delegatingConfigService.updateConfigService(dynamicConfigService);
        } else {
            logger.info("Switching to StaticConfigService");
            this.delegatingConfigService.updateConfigService(staticConfigService);
        }
    }

    public IConfigService getDelegatingConfigService() {
        return delegatingConfigService;
    }

}
