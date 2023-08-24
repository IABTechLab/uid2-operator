package com.uid2.operator;

import com.uid2.shared.cloud.EmbeddedResourceStorage;

import com.uid2.shared.store.CloudPath;
import com.uid2.shared.store.reader.RotatingKeysetKeyStore;
import com.uid2.shared.store.scope.GlobalScope;
import io.vertx.core.json.JsonObject;
import org.junit.Test;

public class RotatingKeysetKeyStoreTest {
    @Test
    public void loadFromEmbeddedResourceStorage() throws Exception {
        RotatingKeysetKeyStore keysetKeyStore = new RotatingKeysetKeyStore(
                new EmbeddedResourceStorage(Main.class),
                new GlobalScope(new CloudPath("/com.uid2.core/test/keyset_keys/metadata.json")));

        JsonObject m = keysetKeyStore.getMetadata();
        keysetKeyStore.loadContent(m);
    }
}
