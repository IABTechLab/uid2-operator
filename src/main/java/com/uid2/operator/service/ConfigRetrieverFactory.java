package com.uid2.operator.service;

import io.vertx.config.ConfigRetriever;
import io.vertx.config.ConfigRetrieverOptions;
import io.vertx.config.ConfigStoreOptions;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;

import java.net.URI;
import java.time.Duration;

import static com.uid2.operator.Const.Config.ConfigScanPeriodMsProp;

public class ConfigRetrieverFactory {
    // TODO
    public static ConfigRetriever create(Vertx vertx, Duration configScanPeriod, ConfigStoreOptions storeOptions) {
//        String type = bootstrapConfig.getString("type");
//        JsonObject storeConfig = bootstrapConfig.getJsonObject("config");
//        if (type.equals("http")) {
//            URI uri = URI.create(storeConfig.getString("url"));
//            storeConfig.remove("url");
//            storeConfig.put("host", uri.getHost());
//            int port = uri.getPort();
//            if (port == -1) {
//                port = uri.getScheme().equals("https") ? 443 : 80;
//            }
//            storeConfig.put("port", port);
//            storeConfig.put("path", uri.getPath());
//            storeConfig.put("ssl", uri.getScheme().equals("https"));
//            storeConfig.put("headers", new JsonObject()
//                    .put("Authorization", "Bearer " + operatorKey));
//        }
//
//        ConfigStoreOptions storeOptions = new ConfigStoreOptions()
//                .setType(type)
//                .setConfig(storeConfig);

        ConfigRetrieverOptions retrieverOptions = new ConfigRetrieverOptions()
                .setScanPeriod(configScanPeriod.toMillis())
                .addStore(storeOptions);

        return ConfigRetriever.create(vertx, retrieverOptions);
    }
}
