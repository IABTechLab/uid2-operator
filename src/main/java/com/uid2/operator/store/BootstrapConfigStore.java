package com.uid2.operator.store;

import io.vertx.core.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BootstrapConfigStore implements IConfigStore {
    private static final Logger logger = LoggerFactory.getLogger(BootstrapConfigStore.class);
    private final RuntimeConfig config;

    public BootstrapConfigStore(JsonObject config) {
        this.config = config.mapTo(RuntimeConfig.class);
        logger.info("Successfully loaded bootstrap config");
    }

    @Override
    public RuntimeConfig getConfig() {
        return config;
    }

    @Override
    public void loadContent() throws Exception {
        logger.info("Remote Config FF is not enabled, bootstrap config was loaded.");
        return;
    }
}
