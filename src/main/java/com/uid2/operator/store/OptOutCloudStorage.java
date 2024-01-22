package com.uid2.operator.store;

import com.uid2.shared.Utils;
import com.uid2.shared.attest.UidOptOutClient;
import com.uid2.shared.cloud.CloudStorageException;
import com.uid2.shared.cloud.URLStorageWithMetadata;
import com.uid2.shared.optout.OptOutMetadata;

import java.io.IOException;
import java.io.InputStream;
import java.net.Proxy;
import java.util.List;
import java.util.stream.Collectors;

public class OptOutCloudStorage extends URLStorageWithMetadata {
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
            OptOutMetadata m = OptOutMetadata.fromJsonString(Utils.readToEnd(input));
            return m.optoutLogs.stream().map(o -> o.location).collect(Collectors.toList());
        } catch (IOException e) {
            throw new CloudStorageException("extractListFromMetadata error" + e.getMessage(), e);
        }
    }
}
