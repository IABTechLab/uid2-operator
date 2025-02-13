package com.uid2.operator.service;

import com.uid2.shared.Utils;
import com.uid2.shared.cloud.DownloadCloudStorage;
import com.uid2.shared.store.reader.IMetadataVersionedStore;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;

import java.io.InputStream;

import static com.uid2.operator.Const.Config.OperatorRuntimeConfigEventBus;

public class RotatingRuntimeConfigStore implements IMetadataVersionedStore {
    private final DownloadCloudStorage metadataStreamProvider;
    private final String runtimeConfigPath;
    private final Vertx vertx;

    public RotatingRuntimeConfigStore(Vertx vertx, DownloadCloudStorage metadataStreamProvider, String runtimeConfigPath) {
        this.metadataStreamProvider = metadataStreamProvider;
        this.runtimeConfigPath = runtimeConfigPath;
        this.vertx = vertx;
    }

    @Override
    public JsonObject getMetadata() throws Exception {
        try (InputStream s = this.metadataStreamProvider.download(this.runtimeConfigPath)) {
            return Utils.toJsonObject(s);
        }
    }

    @Override
    public long getVersion(JsonObject jsonObject) {
        return jsonObject.getLong("version");
    }

    @Override
    public long loadContent(JsonObject jsonObject) throws Exception {
        vertx.eventBus().publish(OperatorRuntimeConfigEventBus, jsonObject);
        return 1;
    }
}
