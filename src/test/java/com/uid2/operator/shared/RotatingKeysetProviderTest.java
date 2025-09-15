package com.uid2.operator.shared;

import com.uid2.operator.Main;
import com.uid2.shared.cloud.EmbeddedResourceStorage;

import com.uid2.shared.store.CloudPath;
import com.uid2.shared.store.reader.RotatingKeysetProvider;
import com.uid2.shared.store.scope.GlobalScope;
import io.vertx.core.json.JsonObject;
import org.junit.jupiter.api.Test;

class RotatingKeysetProviderTest {
    @Test
    void loadFromEmbeddedResourceStorage() throws Exception {
        RotatingKeysetProvider keysetProvider = new RotatingKeysetProvider(
                new EmbeddedResourceStorage(Main.class),
                new GlobalScope(new CloudPath("/com.uid2.core/test/keysets/metadata.json")));

        JsonObject m = keysetProvider.getMetadata();
        keysetProvider.loadContent(m);
    }
}
