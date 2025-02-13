package com.uid2.operator;

import com.uid2.operator.service.RotatingRuntimeConfigStore;
import com.uid2.shared.cloud.EmbeddedResourceStorage;
import com.uid2.shared.cloud.ICloudStorage;
import io.vertx.core.Vertx;
import io.vertx.core.eventbus.EventBus;
import io.vertx.core.json.JsonObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

import static com.uid2.operator.Const.Config.OperatorRuntimeConfigEventBus;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class RotatingRuntimeConfigStoreTest {
    private AutoCloseable mocks;
    @Mock
    private ICloudStorage metadataStreamProvider;
    @Mock
    private Vertx vertx;
    @Mock
    private EventBus eventBus;

    private RotatingRuntimeConfigStore rotatingRuntimeConfigStore;
    private final String runtimeConfigPath = "/com.uid2.core/test/runtime_config/metadata.json";

    @BeforeEach
    public void setup() {
        mocks = MockitoAnnotations.openMocks(this);
        when(vertx.eventBus()).thenReturn(eventBus);
        rotatingRuntimeConfigStore = new RotatingRuntimeConfigStore(vertx, metadataStreamProvider, runtimeConfigPath);
    }

    @AfterEach
    public void teardown() throws Exception {
        mocks.close();
    }

    @Test
    public void testGetMetadata() throws Exception {
        JsonObject expectedMetadata = new JsonObject().put("key", "value");
        when(metadataStreamProvider.download(runtimeConfigPath))
                .thenReturn(new ByteArrayInputStream(expectedMetadata.toString().getBytes(StandardCharsets.US_ASCII)));
        JsonObject actualMetadata = rotatingRuntimeConfigStore.getMetadata();
        assertEquals(expectedMetadata, actualMetadata);
    }

    @Test
    public void testGetVersion() {
        JsonObject jsonObject = new JsonObject().put("version", 123L);
        long version = rotatingRuntimeConfigStore.getVersion(jsonObject);
        assertEquals(123L, version);
    }

    @Test
    public void testLoadContent() throws Exception {
        JsonObject jsonObject = new JsonObject().put("key", "value");
        long result = rotatingRuntimeConfigStore.loadContent(jsonObject);
        verify(eventBus).publish(OperatorRuntimeConfigEventBus, jsonObject);
        assertEquals(1L, result);
    }

    @Test
    public void loadFromEmbeddedResourceStorage() throws Exception {
        rotatingRuntimeConfigStore = new RotatingRuntimeConfigStore(vertx, new EmbeddedResourceStorage(Main.class), runtimeConfigPath);
        JsonObject m = rotatingRuntimeConfigStore.getMetadata();
        rotatingRuntimeConfigStore.loadContent(m);
    }
}
