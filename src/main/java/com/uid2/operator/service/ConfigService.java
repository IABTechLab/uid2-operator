package com.uid2.operator.service;

import com.uid2.operator.Const;
import io.vertx.config.ConfigRetriever;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.atomic.AtomicReference;

import static com.uid2.operator.service.ConfigValidatorUtil.*;
import static com.uid2.operator.service.UIDOperatorService.*;

public class ConfigService implements IConfigService {

    private final AtomicReference<JsonObject> config = new AtomicReference<>();
    private final ConfigRetriever configRetriever;
    private static final Logger logger = LoggerFactory.getLogger(ConfigService.class);

    private ConfigService(ConfigRetriever configRetriever) {
        this.configRetriever = configRetriever;
    }
    
    private Future<Void> start() {
        Promise<Void> promise = Promise.promise();
        configRetriever.listen(configChange -> {
            // Return when we have some valid config.
            if (!configChange.getNewConfiguration().isEmpty()) {
                if (isConfigValid(configChange.getNewConfiguration())) {
                    if (this.config.getAndSet(configChange.getNewConfiguration()) == null) {
                        // Complete the promise when we have our first valid config values.
                        promise.complete();
                    }
                    logger.info("Successfully updated config");
                } else {
                    logger.error("Failed to update config");
                }
            }
        });
        
        return promise.future();
//
//        // Maybe we should listen on the stream instead...
//        // This could conflict with Kat's changes.
//        configRetriever.setConfigurationProcessor(this::configValidationHandler);
    }

    public static Future<ConfigService> create(ConfigRetriever configRetriever) {
        // Not necessarily true! At this point, configRetriever has returned some config...
//        Promise<ConfigService> promise = Promise.promise();

        ConfigService instance = new ConfigService(configRetriever);
        Future<Void> start = instance.start();

        // Prevent dependent classes from attempting to access configuration before it has been retrieved.
//        configRetriever.getConfig(ar -> {
//            if (ar.succeeded()) {
//                logger.info("Successfully loaded config");
//                promise.complete(instance);
//            } else {
//                logger.error("Failed to load config: {}", ar.cause().getMessage());
//                promise.fail(ar.cause());
//            }
//        });

        return start.map(instance);
    }

    @Override
    public JsonObject getConfig() {
        return this.config.get();
    }

    private static boolean isConfigValid(JsonObject config) {
        boolean isValid = true;
        Integer identityExpiresAfter = config.getInteger(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS);
        Integer refreshExpiresAfter = config.getInteger(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS);
        Integer refreshIdentityAfter = config.getInteger(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS);
        Integer maxBidstreamLifetimeSeconds = config.getInteger(Const.Config.MaxBidstreamLifetimeSecondsProp, identityExpiresAfter);
        Integer sharingTokenExpiry = config.getInteger(Const.Config.SharingTokenExpiryProp);

        isValid &= validateIdentityRefreshTokens(identityExpiresAfter, refreshExpiresAfter, refreshIdentityAfter);

        isValid &= validateBidstreamLifetime(maxBidstreamLifetimeSeconds, identityExpiresAfter);

        isValid &= validateSharingTokenExpiry(sharingTokenExpiry);

        return isValid;
//        if (!isValid) {
//            logger.error("Failed to update config");
//            JsonObject lastConfig = this.getConfig();
//            if (lastConfig == null || lastConfig.isEmpty()) {
//                throw new RuntimeException("Invalid config retrieved and no previous config to revert to");
//            }
//            return lastConfig;
//        }
//
//        logger.info("Successfully updated config");
//        return config;
    }
}
