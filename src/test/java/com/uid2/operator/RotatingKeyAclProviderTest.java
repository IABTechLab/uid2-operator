package com.uid2.operator;

import com.uid2.shared.cloud.EmbeddedResourceStorage;
import com.uid2.shared.store.CloudPath;
import com.uid2.shared.store.reader.RotatingKeyAclProvider;
import com.uid2.shared.store.scope.GlobalScope;
import io.vertx.core.json.JsonObject;
import org.junit.Test;

public class RotatingKeyAclProviderTest {
    @Test
    public void loadFromEmbeddedResourceStorage() throws Exception {
        RotatingKeyAclProvider keyAclProvider = new RotatingKeyAclProvider(
                new EmbeddedResourceStorage(Main.class),
                new GlobalScope(new CloudPath("/com.uid2.core/test/keys_acl/metadata.json")));

        JsonObject m = keyAclProvider.getMetadata();
        keyAclProvider.loadContent(m);
    }
}
