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

    public RotatingCloudEncryptionKeyApiProvider(DownloadCloudStorage fileStreamProvider, StoreScope scope) {
        super(fileStreamProvider, scope, new ApiStoreReader<>(fileStreamProvider, scope, new CloudEncryptionKeyParser(), "cloud_encryption_keys"));
    }

    public RotatingCloudEncryptionKeyApiProvider(DownloadCloudStorage fileStreamProvider, StoreScope scope, ApiStoreReader<Map<Integer, CloudEncryptionKey>> reader) {
        super(fileStreamProvider, scope, reader);
    }


    @Override
    public long getVersion(JsonObject metadata) {
        // Since we are pulling from an api not a data file, we use the epoch time we got the keys as the version
        return Instant.now().getEpochSecond();
    }
}

