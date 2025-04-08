package com.uid2.operator;

import com.uid2.operator.store.RuntimeConfig;
import com.uid2.operator.store.RuntimeConfigStore;
import com.uid2.shared.cloud.ICloudStorage;
import io.vertx.core.json.JsonObject;
import io.vertx.junit5.VertxExtension;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(VertxExtension.class)
public class RuntimeConfigStoreTest {
    private AutoCloseable mocks;
    private RuntimeConfig runtimeConfig;
    private JsonObject config = new JsonObject();
    @Mock
    private ICloudStorage cloudStorage;

    @BeforeEach
    public void setup() {
        mocks = MockitoAnnotations.openMocks(this);
        setupConfig(config);
        runtimeConfig = setupRuntimeConfig(config);
    }

    private void setupConfig(JsonObject config) {
        config.put("identity_token_expires_after_seconds", 3600);
        config.put("refresh_token_expires_after_seconds", 86400);
        config.put("refresh_identity_token_after_seconds", 900);
        config.put("sharing_token_expiry_seconds", 2592000);
    }

    private RuntimeConfig setupRuntimeConfig(JsonObject config) {
        return config.mapTo(RuntimeConfig.class);
    }

    @AfterEach
    public void teardown() throws Exception {
        mocks.close();
    }

    @Test
    public void loadRuntimeConfigSingleVersion() throws Exception {
        final JsonObject metadataJson = new JsonObject();
        metadataJson.put("version", 2);
        metadataJson.put("runtime_config", this.config);

        when(cloudStorage.download("metadata"))
                .thenReturn(new ByteArrayInputStream(metadataJson.toString().getBytes(StandardCharsets.US_ASCII)));

        RuntimeConfigStore runtimeConfigStore = new RuntimeConfigStore(cloudStorage, "metadata");

        final JsonObject loadedMetadata = runtimeConfigStore.getMetadata();
        runtimeConfigStore.loadContent(loadedMetadata);
        assertEquals(2, runtimeConfigStore.getVersion(loadedMetadata));
        assertThat(runtimeConfigStore.getConfig())
                .usingRecursiveComparison()
                .isEqualTo(this.runtimeConfig);
    }

    @Test
    public void testFirstInvalidConfigThrowsRuntimeException() throws Exception {
        JsonObject invalidConfig = new JsonObject()
                .put("identity_token_expires_after_seconds", 1000)
                .put("refresh_token_expires_after_seconds", 2000);

        final JsonObject metadataJson = new JsonObject();
        metadataJson.put("version", 1);
        metadataJson.put("runtime_config", invalidConfig);

        when(cloudStorage.download("metadata"))
                .thenReturn(new ByteArrayInputStream(metadataJson.toString().getBytes(StandardCharsets.US_ASCII)));

        RuntimeConfigStore runtimeConfigStore = new RuntimeConfigStore(cloudStorage, "metadata");

        final JsonObject loadedMetadata = runtimeConfigStore.getMetadata();
        assertThrows(RuntimeException.class, () -> {
            runtimeConfigStore.loadContent(loadedMetadata);
        }, "Expected a RuntimeException but the creation succeeded");
    }

    @Test
    public void testInvalidConfigRevertsToPrevious() throws Exception {
        JsonObject invalidConfig = new JsonObject()
                .put("identity_token_expires_after_seconds", 1000)
                .put("refresh_token_expires_after_seconds", 2000);

        final JsonObject v1MetadataJson = new JsonObject();
        v1MetadataJson.put("version", 1);
        v1MetadataJson.put("runtime_config", this.config);
        final JsonObject v2MetadataJson = new JsonObject();
        v2MetadataJson.put("version", 2);
        v2MetadataJson.put("runtime_config", invalidConfig);

        RuntimeConfigStore runtimeConfigStore = new RuntimeConfigStore(cloudStorage, "metadata");

        // First call, return valid config
        when(cloudStorage.download("metadata"))
                .thenReturn(new ByteArrayInputStream(v1MetadataJson.toString().getBytes(StandardCharsets.US_ASCII)));

        final JsonObject loadedMetadata1 = runtimeConfigStore.getMetadata();
        runtimeConfigStore.loadContent(loadedMetadata1);
        assertEquals(1, runtimeConfigStore.getVersion(loadedMetadata1));
        assertThat(runtimeConfigStore.getConfig())
                .usingRecursiveComparison()
                .isEqualTo(this.runtimeConfig);

        // Second call, return invalid config
        when(cloudStorage.download("metadata"))
                .thenReturn(new ByteArrayInputStream(v2MetadataJson.toString().getBytes(StandardCharsets.US_ASCII)));

        final JsonObject loadedMetadata2 = runtimeConfigStore.getMetadata();
        assertThrows(IllegalArgumentException.class, () -> runtimeConfigStore.loadContent(loadedMetadata2));
        assertThat(runtimeConfigStore.getConfig())
                .usingRecursiveComparison()
                .isEqualTo(this.runtimeConfig);
    }
}
