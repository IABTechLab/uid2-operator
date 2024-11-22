package com.uid2.operator.reader;

import com.uid2.shared.cloud.DownloadCloudStorage;
import com.uid2.shared.model.CloudEncryptionKey;
import com.uid2.shared.store.CloudPath;
import com.uid2.shared.store.parser.CloudEncryptionKeyParser;
import com.uid2.shared.store.reader.RotatingCloudEncryptionKeyProvider;
import com.uid2.shared.store.scope.StoreScope;
import io.vertx.core.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.*;

public class RotatingCloudEncryptionKeyApiProvider extends RotatingCloudEncryptionKeyProvider {
    private static final Logger LOGGER = LoggerFactory.getLogger(RotatingCloudEncryptionKeyApiProvider.class);

    public ApiStoreReader<Map<Integer, CloudEncryptionKey>> apiStoreReader;

    public RotatingCloudEncryptionKeyApiProvider(DownloadCloudStorage fileStreamProvider, StoreScope scope) {
        super(fileStreamProvider, scope);
        this.apiStoreReader = new ApiStoreReader<>(fileStreamProvider, scope, new CloudEncryptionKeyParser(), "cloud_encryption_keys");
    }

    @Override
    public JsonObject getMetadata() throws Exception {
        return apiStoreReader.getMetadata();
    }

    @Override
    public CloudPath getMetadataPath() {
        return apiStoreReader.getMetadataPath();
    }

    @Override
    public long loadContent(JsonObject metadata) throws Exception {
        return apiStoreReader.loadContent(metadata, "s3Keys");
    }

    @Override
    public long getVersion(JsonObject metadata) {
        return Instant.now().getEpochSecond();
    }

    @Override
    public Map<Integer, CloudEncryptionKey> getAll() {
        Map<Integer, CloudEncryptionKey> keys = apiStoreReader.getSnapshot();
        return keys != null ? keys : new HashMap<>();
    }

    @Override
    public void loadContent() throws Exception {
        this.loadContent(this.getMetadata());
    }
}
