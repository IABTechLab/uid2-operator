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
    private final String address;

    public ConfigStore(DownloadCloudStorage fileStreamProvider, Vertx vertx, String address) {
        this.fileStreamProvider = fileStreamProvider;
        this.vertx = vertx;
        this.address = address;
    }
    
    @Override
    public JsonObject getMetadata() throws Exception {
        // TODO
        try (InputStream s = this.fileStreamProvider.download("http://localhost:8088/operator/config")) {
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
        this.vertx.eventBus().publish(address, metadata);
        return 1;
    }
}
