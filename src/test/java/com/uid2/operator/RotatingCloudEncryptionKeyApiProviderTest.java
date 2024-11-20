package com.uid2.operator;

import com.uid2.operator.reader.ApiStoreReader;
import com.uid2.operator.reader.RotatingCloudEncryptionKeyApiProvider;
import com.uid2.shared.cloud.DownloadCloudStorage;
import com.uid2.shared.model.CloudEncryptionKey;
import com.uid2.shared.store.CloudPath;
import com.uid2.shared.store.scope.StoreScope;
import io.vertx.core.json.JsonObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class RotatingCloudEncryptionKeyApiProviderTest {

    @Mock
    private DownloadCloudStorage mockFileStreamProvider;

    @Mock
    private StoreScope mockScope;

    @Mock
    private ApiStoreReader<Map<Integer, CloudEncryptionKey>> mockApiStoreReader;

    private RotatingCloudEncryptionKeyApiProvider rotatingCloudEncryptionKeyApiProvider;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        rotatingCloudEncryptionKeyApiProvider = new RotatingCloudEncryptionKeyApiProvider(mockFileStreamProvider, mockScope);
        rotatingCloudEncryptionKeyApiProvider.apiStoreReader = mockApiStoreReader;
    }

    @Test
    void testGetMetadata() throws Exception {
        JsonObject expectedMetadata = new JsonObject().put("version", 1L);
        when(mockApiStoreReader.getMetadata()).thenReturn(expectedMetadata);

        JsonObject metadata = rotatingCloudEncryptionKeyApiProvider.getMetadata();
        assertEquals(expectedMetadata, metadata);
        verify(mockApiStoreReader).getMetadata();
    }

    @Test
    void testGetMetadataPath() {
        CloudPath expectedPath = new CloudPath("test/path");
        when(mockApiStoreReader.getMetadataPath()).thenReturn(expectedPath);

        CloudPath path = rotatingCloudEncryptionKeyApiProvider.getMetadataPath();
        assertEquals(expectedPath, path);
        verify(mockApiStoreReader).getMetadataPath();
    }

    @Test
    void testLoadContentWithMetadata() throws Exception {
        JsonObject metadata = new JsonObject();
        when(mockApiStoreReader.loadContent(metadata, "s3Keys")).thenReturn(1L);

        long version = rotatingCloudEncryptionKeyApiProvider.loadContent(metadata);
        assertEquals(1L, version);
        verify(mockApiStoreReader).loadContent(metadata, "s3Keys");
    }

    @Test
    void testGetAll() {
        Map<Integer, CloudEncryptionKey> expectedKeys = new HashMap<>();
        CloudEncryptionKey key = new CloudEncryptionKey(1, 123, 1687635529, 1687808329, "secret");
        expectedKeys.put(1, key);
        when(mockApiStoreReader.getSnapshot()).thenReturn(expectedKeys);

        Map<Integer, CloudEncryptionKey> keys = rotatingCloudEncryptionKeyApiProvider.getAll();
        assertEquals(expectedKeys, keys);
        verify(mockApiStoreReader).getSnapshot();
    }

    @Test
    void testGetAllWithNullSnapshot() {
        when(mockApiStoreReader.getSnapshot()).thenReturn(null);

        Map<Integer, CloudEncryptionKey> keys = rotatingCloudEncryptionKeyApiProvider.getAll();
        assertNotNull(keys);
        assertTrue(keys.isEmpty());
        verify(mockApiStoreReader).getSnapshot();
    }

    @Test
    void testLoadContent() throws Exception {
        JsonObject metadata = new JsonObject().put("version", 1L);
        when(mockApiStoreReader.getMetadata()).thenReturn(metadata);
        when(mockApiStoreReader.loadContent(metadata, "s3Keys")).thenReturn(1L);

        rotatingCloudEncryptionKeyApiProvider.loadContent();
        verify(mockApiStoreReader).getMetadata();
        verify(mockApiStoreReader).loadContent(metadata, "s3Keys");
    }
}