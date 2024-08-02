package com.uid2.operator.reader;

import com.uid2.operator.reader.ApiStoreReader;
import com.uid2.shared.cloud.DownloadCloudStorage;
import com.uid2.shared.model.S3Key;
import com.uid2.shared.store.CloudPath;
import com.uid2.shared.store.parser.S3KeyParser;
import com.uid2.shared.store.reader.RotatingS3KeyProvider;
import com.uid2.shared.store.scope.StoreScope;
import io.vertx.core.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

public class RotatingS3KeyOperatorProvider extends RotatingS3KeyProvider {
    private static final Logger LOGGER = LoggerFactory.getLogger(RotatingS3KeyOperatorProvider.class);

    private final ApiStoreReader<Map<Integer, S3Key>> apiStoreReader;

    public RotatingS3KeyOperatorProvider(DownloadCloudStorage fileStreamProvider, StoreScope scope) {
        super(fileStreamProvider, scope);
        this.apiStoreReader = new ApiStoreReader<>(fileStreamProvider, scope, new S3KeyParser(), "s3encryption_keys");
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
    public Map<Integer, S3Key> getAll() {
        Map<Integer, S3Key> keys = apiStoreReader.getSnapshot();
        return keys != null ? keys : new HashMap<>();
    }

    @Override
    public void loadContent() throws Exception {
        this.loadContent(this.getMetadata());
    }
}
