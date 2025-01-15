package com.uid2.operator.service;

import io.vertx.config.ConfigRetriever;
import io.vertx.config.ConfigRetrieverOptions;
import io.vertx.config.ConfigStoreOptions;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;

import java.net.URI;
import java.net.URISyntaxException;

import static com.uid2.operator.Const.Config.ConfigScanPeriodMs;
import static com.uid2.operator.Const.Config.CoreConfigPath;

public class ConfigRetrieverFactory {
    public ConfigRetriever createRemoteConfigRetriever(Vertx vertx, JsonObject bootstrapConfig, String operatorKey) throws URISyntaxException {
        String configPath = bootstrapConfig.getString(CoreConfigPath);
        URI uri = new URI(configPath);

        ConfigStoreOptions httpStore = new ConfigStoreOptions()
                .setType("http")
                .setOptional(true)
                .setConfig(new JsonObject()
                        .put("host", uri.getHost())
                        .put("port", uri.getPort())
                        .put("path", uri.getPath())
                        .put("headers", new JsonObject()
                                .put("Authorization", "Bearer " + operatorKey)));

        ConfigRetrieverOptions retrieverOptions = new ConfigRetrieverOptions()
                .setScanPeriod(bootstrapConfig.getLong(ConfigScanPeriodMs))
                .addStore(httpStore);

        return ConfigRetriever.create(vertx, retrieverOptions);
    }

    public ConfigRetriever createJsonRetriever(Vertx vertx, JsonObject config) {
        ConfigStoreOptions jsonStore = new ConfigStoreOptions()
                .setType("json")
                .setConfig(config);

        ConfigRetrieverOptions retrieverOptions = new ConfigRetrieverOptions()
                .setScanPeriod(-1)
                .addStore(jsonStore);


        return ConfigRetriever.create(vertx, retrieverOptions);
    }

    public ConfigRetriever createFileRetriever(Vertx vertx, String path) {
        ConfigStoreOptions fileStore = new ConfigStoreOptions()
                .setType("file")
                .setConfig(new JsonObject()
                        .put("path", path)
                        .put("format", "json"));

        ConfigRetrieverOptions retrieverOptions = new ConfigRetrieverOptions()
                .addStore(fileStore);

        return ConfigRetriever.create(vertx, retrieverOptions);
    }
}
