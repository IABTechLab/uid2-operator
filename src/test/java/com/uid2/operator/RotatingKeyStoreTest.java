package com.uid2.operator;

import com.uid2.shared.cloud.EmbeddedResourceStorage;

import com.uid2.shared.store.CloudPath;
import com.uid2.shared.store.reader.RotatingKeyStore;
import com.uid2.shared.store.scope.GlobalScope;
import io.vertx.core.json.JsonObject;
import org.junit.Test;

public class RotatingKeyStoreTest {
    @Test public void loadFromEmbeddedResourceStorage() throws Exception {
        RotatingKeyStore fileProvider = new RotatingKeyStore(
            new EmbeddedResourceStorage(Main.class),
                new GlobalScope(new CloudPath("/com.uid2.core/test/keys/metadata.json")));

        JsonObject m = fileProvider.getMetadata();
        fileProvider.loadContent(m);
    }
}
