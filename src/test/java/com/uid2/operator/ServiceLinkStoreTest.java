package com.uid2.operator;

import com.uid2.shared.cloud.EmbeddedResourceStorage;
import com.uid2.shared.store.CloudPath;
import com.uid2.shared.store.reader.RotatingServiceLinkStore;
import com.uid2.shared.store.scope.GlobalScope;
import io.vertx.core.json.JsonObject;
import org.junit.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

public class ServiceLinkStoreTest {
    @Test
    public void loadFromEmbeddedResourceStorage() throws Exception {
        RotatingServiceLinkStore fileProvider = new RotatingServiceLinkStore(
                new EmbeddedResourceStorage(Main.class),
                new GlobalScope(new CloudPath("/com.uid2.core/test/service_links/metadata.json")));

        JsonObject m = fileProvider.getMetadata();
        assertDoesNotThrow(() -> fileProvider.loadContent(m));
    }
}
