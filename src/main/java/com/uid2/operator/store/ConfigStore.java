package com.uid2.operator.store;

import com.uid2.shared.Utils;
import com.uid2.shared.cloud.DownloadCloudStorage;
import com.uid2.shared.store.reader.IMetadataVersionedStore;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;

import java.io.InputStream;

public class ConfigStore implements IMetadataVersionedStore {
    private final DownloadCloudStorage fileStreamProvider;
    private final Vertx vertx;
    private final String configMetadataPath;
    private final String address;

    public ConfigStore(Vertx vertx, DownloadCloudStorage fileStreamProvider, String configMetadataPath, String address) {
        this.fileStreamProvider = fileStreamProvider;
        this.vertx = vertx;
        this.configMetadataPath = configMetadataPath;
        this.address = address;
    }
    
    @Override
    public JsonObject getMetadata() throws Exception {
        // TODO
        try (InputStream s = this.fileStreamProvider.download(configMetadataPath)) {
            return Utils.toJsonObject(s);
        }
//        this.fileStreamProvider.download()
//        return null;
    }

    @Override
    public long getVersion(JsonObject metadata) {
        return metadata.getLong("version");
    }

    @Override
    public long loadContent(JsonObject metadata) throws Exception {
        this.vertx.eventBus().publish(address, metadata.getJsonObject("config"));
        return 1;
    }
}
