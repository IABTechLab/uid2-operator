package com.uid2.operator.service;

import io.vertx.config.ConfigRetriever;
import io.vertx.config.ConfigRetrieverOptions;
import io.vertx.config.ConfigStoreOptions;
import io.vertx.core.Vertx;

import java.time.Duration;

public class ConfigRetrieverFactory {
    public static ConfigRetriever create(Vertx vertx, Duration configScanPeriod, ConfigStoreOptions storeOptions) {
        ConfigRetrieverOptions retrieverOptions = new ConfigRetrieverOptions()
                .setScanPeriod(configScanPeriod.toMillis())
                .addStore(storeOptions);

        return ConfigRetriever.create(vertx, retrieverOptions);
    }
}
