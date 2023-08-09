package com.uid2.operator;

import com.uid2.shared.cloud.EmbeddedResourceStorage;
import com.uid2.shared.store.CloudPath;
import com.uid2.shared.store.reader.RotatingClientSideKeypairStore;
import com.uid2.shared.store.reader.RotatingKeyAclProvider;
import com.uid2.shared.store.scope.GlobalScope;
import io.vertx.core.json.JsonObject;
import org.junit.Test;

public class RotatingClientSideKeypairStoreTest {
    @Test
    public void loadFromEmbeddedResourceStorage() throws Exception {
        RotatingClientSideKeypairStore keypairProvider = new RotatingClientSideKeypairStore(
                new EmbeddedResourceStorage(Main.class),
                new GlobalScope(new CloudPath("/com.uid2.core/test/client_side_keypairs/metadata.json")));

        JsonObject m = keypairProvider.getMetadata();
        keypairProvider.loadContent(m);
    }
}
