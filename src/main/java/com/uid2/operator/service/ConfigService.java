package com.uid2.operator.service;

import com.uid2.operator.Const;
import io.vertx.config.ConfigRetriever;
import io.vertx.config.ConfigRetrieverOptions;
import io.vertx.config.ConfigStoreOptions;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static com.uid2.operator.Const.Config.*;
import static com.uid2.operator.service.ConfigValidatorUtil.*;
import static com.uid2.operator.service.UIDOperatorService.*;

public class ConfigService implements IConfigService {

    private static volatile ConfigService instance;
    private ConfigRetriever configRetriever;
    private static final Logger logger = LoggerFactory.getLogger(ConfigService.class);

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
        String configPath = bootstrapConfig.getString(CoreConfigPath);


        ConfigStoreOptions httpStore = new ConfigStoreOptions()
                .setType("http")
                .setConfig(new JsonObject()
                        .put("host", "127.0.0.1")
                        .put("port", Const.Port.ServicePortForCore)
                        .put("path", configPath));

        ConfigStoreOptions bootstrapStore = new ConfigStoreOptions()
                .setType("json")
                .setConfig(bootstrapConfig);

        ConfigRetrieverOptions retrieverOptions = new ConfigRetrieverOptions()
                .setScanPeriod(bootstrapConfig.getLong(ConfigScanPeriodMs))
                .addStore(bootstrapStore)
                .addStore(httpStore);

        this.configRetriever = ConfigRetriever.create(vertx, retrieverOptions);

        this.configRetriever.setConfigurationProcessor(this::configValidationHandler);

        this.configRetriever.getConfig(ar -> {
            if (ar.succeeded()) {
                System.out.println("Successfully loaded config");
            } else {
                System.err.println("Failed to load config: " + ar.cause().getMessage());
                logger.error("Failed to load config");
            }
        });

    }

    private JsonObject configValidationHandler(JsonObject config) {
        boolean isValid = true;
        Integer identityExpiresAfter = config.getInteger(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS);
        Integer refreshExpiresAfter = config.getInteger(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS);
        Integer refreshIdentityAfter = config.getInteger(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS);
        Integer maxBidstreamLifetimeSeconds = config.getInteger(Const.Config.MaxBidstreamLifetimeSecondsProp);

        isValid &= validateIdentityRefreshTokens(identityExpiresAfter, refreshExpiresAfter, refreshIdentityAfter);

        isValid &= validateBidstreamLifetime(maxBidstreamLifetimeSeconds, identityExpiresAfter);

        if (!isValid) {
            logger.error("Failed to update config");
            JsonObject lastConfig = this.getConfig();
            if (lastConfig == null || lastConfig.isEmpty()) {
                throw new RuntimeException("Invalid config retrieved and no previous config to revert to");
            }
            return lastConfig;
        }

        return config;
    }
}
