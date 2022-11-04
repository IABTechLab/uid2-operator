package com.uid2.operator;

import com.uid2.shared.store.RotatingKeyStore;
import com.uid2.shared.cloud.EmbeddedResourceStorage;

import io.vertx.core.json.JsonObject;
import org.junit.Test;

public class RotatingKeyStoreTest {
    @Test public void loadFromEmbeddedResourceStorage() throws Exception {
        RotatingKeyStore fileProvider = new RotatingKeyStore(
            new EmbeddedResourceStorage(Main.class),
            "/com.uid2.core/test/keys/metadata.json");;

        JsonObject m = fileProvider.getMetadata();
        fileProvider.loadContent(m);
    }
}
