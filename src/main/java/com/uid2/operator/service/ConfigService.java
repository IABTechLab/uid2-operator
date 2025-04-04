package com.uid2.operator.service;

import com.uid2.operator.Const;
import com.uid2.operator.model.RuntimeConfig;
import io.vertx.config.ConfigRetriever;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.uid2.operator.service.ConfigValidatorUtil.*;
import static com.uid2.operator.service.UIDOperatorService.*;

public class ConfigService implements IConfigService {

    private final ConfigRetriever configRetriever;
    private static final Logger logger = LoggerFactory.getLogger(ConfigService.class);

    private ConfigService(ConfigRetriever configRetriever) {
        this.configRetriever = configRetriever;
        this.configRetriever.setConfigurationProcessor(this::configValidationHandler);
    }

    public static Future<ConfigService> create(ConfigRetriever configRetriever) {
        Promise<ConfigService> promise = Promise.promise();

        ConfigService instance = new ConfigService(configRetriever);

        // Prevent dependent classes from attempting to access configuration before it has been retrieved.
        configRetriever.getConfig(ar -> {
            if (ar.succeeded()) {
                logger.info("Successfully loaded config");
                promise.complete(instance);
            } else {
                logger.error("Failed to load config: {}", ar.cause().getMessage());
                promise.fail(ar.cause());
            }
        });

        return promise.future();
    }

    @Override
    public RuntimeConfig getConfig() {
        return configRetriever.getCachedConfig().mapTo(RuntimeConfig.class);
    }

    private JsonObject configValidationHandler(JsonObject config) {
        RuntimeConfig runtimeConfig = config.mapTo(RuntimeConfig.class);

        if (!runtimeConfig.isValid()) {
            logger.error("Failed to update config");
            RuntimeConfig lastConfig = this.getConfig();
            if (lastConfig == null || !lastConfig.isValid()) {
                throw new RuntimeException("Invalid config retrieved and no previous config to revert to");
            }
            return JsonObject.mapFrom(lastConfig);
        }

        logger.info("Successfully updated config");
        return config;
    }
}
