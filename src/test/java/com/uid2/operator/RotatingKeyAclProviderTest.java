package com.uid2.operator;

import com.uid2.shared.auth.RotatingKeyAclProvider;
import com.uid2.shared.cloud.EmbeddedResourceStorage;
import io.vertx.core.json.JsonObject;
import org.junit.Test;

public class RotatingKeyAclProviderTest {
    @Test
    public void loadFromEmbeddedResourceStorage() throws Exception {
        RotatingKeyAclProvider keyAclProvider = new RotatingKeyAclProvider(
                new EmbeddedResourceStorage(Main.class),
                "/com.uid2.core/test/keys_acl/metadata.json");;

        JsonObject m = keyAclProvider.getMetadata();
        keyAclProvider.loadContent(m);
    }
}
