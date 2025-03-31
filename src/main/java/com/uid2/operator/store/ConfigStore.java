package com.uid2.operator.store;

import com.uid2.shared.Utils;
import com.uid2.shared.cloud.DownloadCloudStorage;
import com.uid2.shared.store.reader.IMetadataVersionedStore;
import io.vertx.core.json.JsonObject;

import java.io.InputStream;

public class ConfigStore implements IMetadataVersionedStore {
    private final DownloadCloudStorage fileStreamProvider;

    public ConfigStore(DownloadCloudStorage fileStreamProvider) {
        this.fileStreamProvider = fileStreamProvider;
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
    public long getVersion(JsonObject jsonObject) {
        return 0;
    }

    @Override
    public long loadContent(JsonObject jsonObject) throws Exception {
        return 0;
    }
}
