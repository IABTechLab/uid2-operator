package com.uid2.operator.store;

import com.uid2.shared.Utils;
import com.uid2.shared.attest.UidOptOutClient;
import com.uid2.shared.cloud.CloudStorageException;
import com.uid2.shared.cloud.URLStorageWithMetadata;
import com.uid2.shared.optout.OptOutMetadata;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.net.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class OptOutCloudStorage extends URLStorageWithMetadata {
    private static final Logger LOGGER = LoggerFactory.getLogger(OptOutCloudStorage.class);

    private final UidOptOutClient uidOptOutClient;
    private final String metadataPath;

    public OptOutCloudStorage(UidOptOutClient uidOptOutClient, String metadataPath) {
        this(uidOptOutClient, metadataPath, null);
    }

    public OptOutCloudStorage(UidOptOutClient uidOptOutClient, String metadataPath, Proxy proxy) {
        super(proxy);
        this.uidOptOutClient = uidOptOutClient;
        this.metadataPath = metadataPath;
    }

    @Override
    protected List<String> extractListFromMetadata() throws CloudStorageException {
        try (InputStream input = this.uidOptOutClient.download(metadataPath)) {
            String jsonString = Utils.readToEnd(input);
            if (jsonString != null && !jsonString.isEmpty()) {
                OptOutMetadata m = OptOutMetadata.fromJsonString(jsonString);
                if (m != null) {
                    return m.optoutLogs.stream().map(o -> o.location).collect(Collectors.toList());
                } else {
                    LOGGER.warn("Unable to parse the OptOut metadata into OptOutMetaData type. Start of the response from OptOut: {}", jsonString.substring(0, jsonString.length() > 50 ? 50 : jsonString.length()));
                    throw new CloudStorageException("Invalid response returned from OptOut.");
                }
            } else {
                LOGGER.warn("Empty string returned from UidOptOutClient. Unable to read OptOut metadata");
                return new ArrayList<String>();
            }
        } catch (Exception e) {
            // Intentionally not logging the exception as it may contain sensitive URLs
            throw new CloudStorageException("extractListFromMetadata error.");
        }
    }
}
