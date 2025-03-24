package com.uid2.operator.store;

import com.uid2.shared.store.reader.IMetadataVersionedStore;
import io.vertx.core.json.JsonObject;

public class ConfigStore implements IMetadataVersionedStore {
    @Override
    public JsonObject getMetadata() throws Exception {
        return null;
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
