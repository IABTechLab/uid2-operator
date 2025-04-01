package com.uid2.operator.service;

import com.uid2.operator.Const;
import io.vertx.config.ConfigRetriever;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.UUID;
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
        // Add a random value to the config, so that configRetriever.configStream()
        // publishes a new value on every scan.
        configRetriever.setConfigurationProcessor(config -> config.put("__config_service_uuid", UUID.randomUUID().toString()));
        configRetriever.configStream()
                .handler(newConfig -> {
                    newConfig.remove("__config_service_uuid");
                    if (newConfig.isEmpty())  {
                        // Event bus config store returns an empty JsonObject if nothing has been published to its address.
                        // Skip empty config values.
                        return;
                    }

                    var oldConfig = this.config.get();
                    if (oldConfig != null && oldConfig.equals(newConfig)) {
                        return;
                    }
                        
                    if (isConfigValid(newConfig)) {
                        this.config.set(newConfig);
                        logger.info("Successfully updated config");
                        if (oldConfig == null) {
                            // Complete the promise when we have our first valid config values.
                            promise.complete();
                        }
                    } else {
                        // TODO: What if we can't get valid config ... should we shut down?
                        // TODO: Should this be communicated with metrics? Via RSV?
                        // If so, we would have to throw an exception from refresh.
                        logger.error("Failed to update config");
                        if (oldConfig == null) {
                            promise.fail("Invalid config retrieved and no previous config to revert to");
                        }
                    }
                });

        return promise.future();
    }

    public static Future<ConfigService> create(ConfigRetriever configRetriever) {
        ConfigService instance = new ConfigService(configRetriever);
        return instance.start().map(instance);
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
    }
}
