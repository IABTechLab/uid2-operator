package com.uid2.operator.service;

import com.uid2.operator.Const;
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
    public JsonObject getConfig() {
        return configRetriever.getCachedConfig();
    }

    private JsonObject configValidationHandler(JsonObject config) {
        boolean isValid = true;
        Integer identityExpiresAfter = config.getInteger(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS);
        Integer refreshExpiresAfter = config.getInteger(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS);
        Integer refreshIdentityAfter = config.getInteger(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS);
        Integer maxBidstreamLifetimeSeconds = config.getInteger(Const.Config.MaxBidstreamLifetimeSecondsProp, identityExpiresAfter);
        Integer sharingTokenExpiry = config.getInteger(Const.Config.SharingTokenExpiryProp);

        isValid &= validateIdentityRefreshTokens(identityExpiresAfter, refreshExpiresAfter, refreshIdentityAfter);

        isValid &= validateBidstreamLifetime(maxBidstreamLifetimeSeconds, identityExpiresAfter);

        isValid &= validateSharingTokenExpiry(sharingTokenExpiry);

        if (!isValid) {
            logger.error("Failed to update config");
            JsonObject lastConfig = this.getConfig();
            if (lastConfig == null || lastConfig.isEmpty()) {
                throw new RuntimeException("Invalid config retrieved and no previous config to revert to");
            }
            return lastConfig;
        }

        logger.info("Successfully updated config");
        return config;
    }
}
