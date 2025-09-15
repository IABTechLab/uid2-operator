package com.uid2.operator.store;

import com.uid2.shared.cloud.ICloudStorage;
import io.vertx.core.json.JsonObject;
import io.vertx.junit5.VertxExtension;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith({VertxExtension.class, MockitoExtension.class})
class RuntimeConfigStoreTest {
    @Mock
    private ICloudStorage cloudStorage;

    private final JsonObject config = new JsonObject();
    private RuntimeConfig runtimeConfig;

    @BeforeEach
    void setup() {
        setupConfig(config);
        runtimeConfig = setupRuntimeConfig(config);
    }

    private void setupConfig(JsonObject config) {
        config.put("identity_token_expires_after_seconds", 3600);
        config.put("refresh_token_expires_after_seconds", 86400);
        config.put("refresh_identity_token_after_seconds", 900);
        config.put("sharing_token_expiry_seconds", 2592000);
        config.put("identity_environment", "test");
    }

    private RuntimeConfig setupRuntimeConfig(JsonObject config) {
        return config.mapTo(RuntimeConfig.class);
    }

    @Test
    void loadRuntimeConfigSingleVersion() throws Exception {
        final JsonObject metadataJson = new JsonObject()
                .put("version", 2)
                .put("runtime_config", this.config);

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
    void testFirstInvalidConfigThrowsRuntimeException() throws Exception {
        JsonObject invalidConfig = new JsonObject()
                .put("identity_token_expires_after_seconds", 1000)
                .put("refresh_token_expires_after_seconds", 2000);

        final JsonObject metadataJson = new JsonObject()
                .put("version", 1)
                .put("runtime_config", invalidConfig);

        when(cloudStorage.download("metadata"))
                .thenReturn(new ByteArrayInputStream(metadataJson.toString().getBytes(StandardCharsets.US_ASCII)));

        RuntimeConfigStore runtimeConfigStore = new RuntimeConfigStore(cloudStorage, "metadata");

        final JsonObject loadedMetadata = runtimeConfigStore.getMetadata();
        assertThrows(RuntimeException.class, () -> {
            runtimeConfigStore.loadContent(loadedMetadata);
        }, "Expected a RuntimeException but the creation succeeded");
    }

    @Test
    void testInvalidConfigRevertsToPrevious() throws Exception {
        JsonObject invalidConfig = new JsonObject()
                .put("identity_token_expires_after_seconds", 1000)
                .put("refresh_token_expires_after_seconds", 2000);

        final JsonObject v1MetadataJson = new JsonObject()
                .put("version", 1)
                .put("runtime_config", this.config);
        final JsonObject v2MetadataJson = new JsonObject()
                .put("version", 2)
                .put("runtime_config", invalidConfig);

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
