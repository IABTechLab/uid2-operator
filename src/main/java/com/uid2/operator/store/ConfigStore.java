package com.uid2.operator.store;

import com.uid2.shared.Utils;
import com.uid2.shared.cloud.DownloadCloudStorage;
import com.uid2.shared.store.reader.IMetadataVersionedStore;
import io.vertx.core.Vertx;
import io.vertx.core.eventbus.EventBus;
import io.vertx.core.json.JsonObject;

import java.io.InputStream;
import java.util.concurrent.atomic.AtomicReference;

public class ConfigStore implements IConfigStore, IMetadataVersionedStore {
    private final DownloadCloudStorage fileStreamProvider;
    private final String configMetadataPath;
    private final AtomicReference<JsonObject> config = new AtomicReference<>();

    public ConfigStore(Vertx vertx, DownloadCloudStorage fileStreamProvider, String configMetadataPath) {
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
        JsonObject config = metadata.getJsonObject("config");
        // TODO: Validation
        this.config.set(config);
        return 1;
    }

    @Override
    public JsonObject getConfig() {
        return config.get();
    }
}
