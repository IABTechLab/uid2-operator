package com.uid2.operator.store;

import io.vertx.core.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BootstrapConfigStore implements IConfigStore {
    private static final Logger logger = LoggerFactory.getLogger(BootstrapConfigStore.class);
    private final JsonObject config;

    public BootstrapConfigStore(JsonObject config) {
        logger.info("Successfully loaded bootstrap config");
        this.config = config;
    }

    @Override
    public RuntimeConfig getConfig() {
        return config.mapTo(RuntimeConfig.class);
    }

    @Override
    public void loadContent() throws Exception {
        logger.info("Remote Config FF is not enabled, bootstrap config was loaded.");
        return;
    }
}
