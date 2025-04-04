package com.uid2.operator.store;

import com.uid2.shared.Utils;
import com.uid2.shared.cloud.DownloadCloudStorage;
import com.uid2.shared.store.reader.IMetadataVersionedStore;
import io.vertx.core.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.util.concurrent.atomic.AtomicReference;

public class RuntimeConfigStore implements IConfigStore, IMetadataVersionedStore {
    private static final Logger logger = LoggerFactory.getLogger(RuntimeConfigStore.class);
    private final DownloadCloudStorage fileStreamProvider;
    private final String configMetadataPath;
    private final AtomicReference<RuntimeConfig> config = new AtomicReference<>();

    public RuntimeConfigStore(DownloadCloudStorage fileStreamProvider, String configMetadataPath) {
        this.fileStreamProvider = fileStreamProvider;
        this.configMetadataPath = configMetadataPath;
    }
    
    @Override
    public JsonObject getMetadata() throws Exception {
        try (InputStream s = this.fileStreamProvider.download(configMetadataPath)) {
            return Utils.toJsonObject(s);
        }
    }

    @Override
    public long getVersion(JsonObject metadata) {
        return metadata.getLong("version");
    }

    @Override
    public long loadContent(JsonObject metadata) throws Exception {
        // The config is returned as part of the metadata itself.
        RuntimeConfig newRuntimeConfig = metadata.getJsonObject("runtime_config").mapTo(RuntimeConfig.class);

        if (!newRuntimeConfig.isValid()) {
            logger.warn("New runtime config invalid, reverting to the last runtime config...");
            RuntimeConfig lastConfig = this.config.get();
            if (lastConfig == null || !lastConfig.isValid()) {
                throw new RuntimeException("Invalid config retrieved and no previous config to revert to");
            }
            this.config.set(lastConfig);
            return 1;
        }

        logger.info("Successfully updated runtime config");
        this.config.set(newRuntimeConfig);
        return 1;
    }

    @Override
    public void loadContent() throws Exception {
        this.loadContent(this.getMetadata());
    }

    @Override
    public RuntimeConfig getConfig() {
        return this.config.get();
    }
}
