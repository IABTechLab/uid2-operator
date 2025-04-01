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
        configRetriever.configStream()
                .handler(newConfig -> {
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
                        if (oldConfig == null) {
                            // Complete the promise when we have our first valid config values.
                            promise.complete();
                        }
                        logger.info("Successfully updated config");
                    } else {
                        logger.error("Failed to update config");
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
