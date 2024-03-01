package com.uid2.operator.store;

import com.uid2.shared.attest.UidOptOutClient;
import com.uid2.shared.cloud.CloudStorageException;
import com.uid2.shared.optout.OptOutMetadata;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.instancio.Instancio;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.mockito.ArgumentMatchers.anyString;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class OptOutCloudStorageTest {
    private UidOptOutClient uidOptOutClient;
    private OptOutCloudStorage optOutCloudStorage;

    @BeforeEach
    public void setUp() {
        this.uidOptOutClient = mock(UidOptOutClient.class);
        this.optOutCloudStorage = new OptOutCloudStorage(this.uidOptOutClient, "/test/path");
    }

    @AfterEach
    public void tearDown() throws Exception {
    }

    @Test
    public void extractListFromMetadata_success() throws CloudStorageException {
        OptOutMetadata m = Instancio.create(OptOutMetadata.class);

        when(uidOptOutClient.download(anyString())).thenReturn(new ByteArrayInputStream(m.toJsonString().getBytes()));

        List<String> response = this.optOutCloudStorage.extractListFromMetadata();

        assertAll("extractListFromMetadata_success valid response",
                () -> assertNotNull(response),
                () -> assertEquals(m.optoutLogs.size(), response.size()),
                () -> assertEquals(m.optoutLogs.stream().findFirst().get().location, response.get(0)));
    }

    @Test
    public void extractListFromMetadata_nullResponse() throws CloudStorageException {
        when(uidOptOutClient.download(anyString())).thenReturn(null);

        assertThrows(CloudStorageException.class,
                () -> this.optOutCloudStorage.extractListFromMetadata());
    }

    @Test
    public void extractListFromMetadata_emptyResponse() throws CloudStorageException {
        when(uidOptOutClient.download(anyString())).thenReturn(InputStream.nullInputStream());

        List<String> response = this.optOutCloudStorage.extractListFromMetadata();
        assertAll("extractListFromMetadata_success valid response",
                () -> assertNotNull(response),
                () -> assertEquals(0, response.size()));
    }

    @Test
    public void extractListFromMetadata_notJsonResponse() throws CloudStorageException {
        when(uidOptOutClient.download(anyString())).thenReturn(new ByteArrayInputStream("Unauthorized".getBytes()));

        assertThrows(CloudStorageException.class,
                () -> this.optOutCloudStorage.extractListFromMetadata());
    }
}
