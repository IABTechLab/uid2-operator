package com.uid2.operator.reader;

import com.uid2.shared.cloud.DownloadCloudStorage;
import com.uid2.shared.store.ScopedStoreReader;
import com.uid2.shared.store.parser.Parser;
import com.uid2.shared.store.parser.ParsingResult;
import com.uid2.shared.store.scope.StoreScope;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public class ApiStoreReader<T> extends ScopedStoreReader<T> {
    private static final Logger LOGGER = LoggerFactory.getLogger(ApiStoreReader.class);

    public ApiStoreReader(DownloadCloudStorage fileStreamProvider, StoreScope scope, Parser<T> parser, String dataTypeName) {
        super(fileStreamProvider, scope, parser, dataTypeName);
    }


    public long loadContent(JsonObject contents) throws Exception {
        return loadContent(contents, dataTypeName);
    }

    @Override
    public long loadContent(JsonObject contents, String dataType) throws IOException {
        if (contents == null) {
            throw new IllegalArgumentException(String.format("No contents provided for loading data type %s, cannot load content", dataType));
        }

        try {
            JsonArray dataArray = contents.getJsonArray(dataType);
            if (dataArray == null) {
                throw new IllegalArgumentException("No array found in the contents");
            }

            String jsonString = dataArray.toString();
            InputStream inputStream = new ByteArrayInputStream(jsonString.getBytes(StandardCharsets.UTF_8));

            ParsingResult<T> parsed = parser.deserialize(inputStream);
            latestSnapshot.set(parsed.getData());

            final int count = parsed.getCount();
            latestEntryCount.set(count);
            LOGGER.info(String.format("Loaded %d %s", count, dataType));
            return count;
        } catch (Exception e) {
            LOGGER.error(String.format("Unable to load %s", dataType));
            throw e;
        }
    }
}
