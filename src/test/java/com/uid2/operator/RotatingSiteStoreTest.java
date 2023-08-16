package com.uid2.operator;

import com.uid2.shared.cloud.EmbeddedResourceStorage;
import com.uid2.shared.store.CloudPath;
import com.uid2.shared.store.reader.RotatingSiteStore;
import com.uid2.shared.store.scope.GlobalScope;
import io.vertx.core.json.JsonObject;
import org.junit.Test;

public class RotatingSiteStoreTest {
    @Test
    public void loadFromEmbeddedResourceStorage() throws Exception {
        RotatingSiteStore siteProvider = new RotatingSiteStore(
                new EmbeddedResourceStorage(Main.class),
                new GlobalScope(new CloudPath("/com.uid2.core/test/sites/metadata.json")));

        JsonObject m = siteProvider.getMetadata();
        siteProvider.loadContent(m);
    }
}
