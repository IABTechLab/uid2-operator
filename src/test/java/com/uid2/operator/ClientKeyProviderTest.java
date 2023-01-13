package com.uid2.operator;

import com.uid2.operator.service.EncodingUtils;
import com.uid2.shared.cloud.EmbeddedResourceStorage;
import com.uid2.shared.store.CloudPath;
import com.uid2.shared.store.reader.RotatingClientKeyProvider;
import com.uid2.shared.store.scope.GlobalScope;
import io.vertx.core.json.JsonObject;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class ClientKeyProviderTest {
    @Test
    public void generateNewClientKeys() throws NoSuchAlgorithmException {
        if (System.getenv("SLOW_DEV_URANDOM") != null) {
            System.err.println("ignore this test since environment variable SLOW_DEV_URANDOM is set");
            return;
        }
        System.out.println("Java VM property java.security.egd: " + System.getProperty("java.security.egd"));
        SecureRandom random = SecureRandom.getInstanceStrong();
        byte[] bytes = new byte[32];
        for (int i = 0; i < 10; ++i) {
            random.nextBytes(bytes);
            System.out.format("client key: %s\n", EncodingUtils.toBase64String(bytes));
        }
    }

    @Test
    public void loadFromEmbeddedResourceStorage() throws Exception {
        RotatingClientKeyProvider fileProvider = new RotatingClientKeyProvider(
            new EmbeddedResourceStorage(Main.class),
                new GlobalScope(new CloudPath("/com.uid2.core/test/clients/metadata.json")));

        JsonObject m = fileProvider.getMetadata();
        fileProvider.loadContent(m);
    }
}
