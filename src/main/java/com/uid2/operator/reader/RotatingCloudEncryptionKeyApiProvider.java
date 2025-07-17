package com.uid2.operator.reader;

import com.uid2.shared.cloud.DownloadCloudStorage;
import com.uid2.shared.model.CloudEncryptionKey;
import com.uid2.shared.store.parser.CloudEncryptionKeyParser;
import com.uid2.shared.store.reader.RotatingCloudEncryptionKeyProvider;
import com.uid2.shared.store.scope.StoreScope;
import io.vertx.core.json.JsonObject;

import java.time.Instant;
import java.util.*;

public class RotatingCloudEncryptionKeyApiProvider extends RotatingCloudEncryptionKeyProvider {
    public RotatingCloudEncryptionKeyApiProvider(DownloadCloudStorage fileStreamProvider, StoreScope scope) {
        super(new ApiStoreReader<>(fileStreamProvider, scope, new CloudEncryptionKeyParser(), "cloud_encryption_keys"));
    }

    public RotatingCloudEncryptionKeyApiProvider(ApiStoreReader<Map<Integer, CloudEncryptionKey>> reader) {
        super(reader);
    }

    @Override
    public long getVersion(JsonObject metadata) {
        // Since we are pulling from an api not a data file, we use the epoch time we got the keys as the version
        return Instant.now().getEpochSecond();
    }
}
