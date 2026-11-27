package com.uid2.operator.store;

import com.uid2.shared.attest.AttestationResponseHandler;
import com.uid2.shared.attest.UidOptOutClient;
import com.uid2.shared.audit.UidInstanceIdProvider;
import com.uid2.shared.cloud.CloudStorageException;
import com.uid2.shared.cloud.MemCachedStorage;
import com.uid2.shared.health.HealthManager;
import com.uid2.shared.optout.OptOutCloudSync;
import com.uid2.shared.optout.OptOutMetadata;
import com.uid2.shared.optout.OptOutUtils;
import com.uid2.shared.util.URLConnectionHttpClient;
import com.uid2.shared.vertx.CloudSyncVerticle;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.junit5.VertxExtension;
import io.vertx.junit5.VertxTestContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.instancio.Instancio;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.ConnectException;
import java.net.UnknownHostException;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Stream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class OptOutCloudStorageTest {
    private static final String EMPTY_METADATA = "{\"version\":1,\"generated\":1,\"optout_logs\":[]}";

    private UidOptOutClient uidOptOutClient;
    private OptOutCloudStorage optOutCloudStorage;

    @BeforeEach
    public void setup() {
        this.uidOptOutClient = mock(UidOptOutClient.class);
        this.optOutCloudStorage = new OptOutCloudStorage(this.uidOptOutClient, "/test/path");
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
    public void extractListFromMetadata_emptyLogList_returnsEmptyList() throws CloudStorageException {
        when(uidOptOutClient.download(anyString())).thenReturn(new ByteArrayInputStream(EMPTY_METADATA.getBytes()));

        assertEquals(0, this.optOutCloudStorage.extractListFromMetadata().size());
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

        CloudStorageException e = assertThrows(CloudStorageException.class,
                () -> this.optOutCloudStorage.extractListFromMetadata());
        assertTrue(e.getMessage().startsWith("E12: Data Download Failure"));
    }

    @Test
    public void extractListFromMetadata_notJsonResponse() throws CloudStorageException {
        when(uidOptOutClient.download(anyString())).thenReturn(new ByteArrayInputStream("Unauthorized".getBytes()));

        assertThrows(CloudStorageException.class,
                () -> this.optOutCloudStorage.extractListFromMetadata());
    }

    @FunctionalInterface
    private interface FailureSetup {
        void apply(URLConnectionHttpClient httpClient, AttestationResponseHandler handler) throws Exception;
    }

    private static Stream<Arguments> downloadFailures() {
        return Stream.of(
                Arguments.of("io error", (FailureSetup) (c, h) -> when(c.get(anyString(), anyMap())).thenThrow(new IOException())),
                Arguments.of("connection refused", (FailureSetup) (c, h) -> when(c.get(anyString(), anyMap())).thenThrow(new ConnectException())),
                Arguments.of("unknown host", (FailureSetup) (c, h) -> when(c.get(anyString(), anyMap())).thenThrow(new UnknownHostException())),
                Arguments.of("http 404", httpStatus(404)),
                Arguments.of("http 500", httpStatus(500)),
                Arguments.of("http 503", httpStatus(503)),
                Arguments.of("no opt-out url", (FailureSetup) (c, h) -> when(h.getOptOutUrl()).thenReturn(null)));
    }

    @SuppressWarnings("unchecked")
    private static FailureSetup httpStatus(int status) {
        return (c, h) -> {
            HttpResponse<String> response = mock(HttpResponse.class);
            when(response.statusCode()).thenReturn(status);
            when(c.get(anyString(), anyMap())).thenReturn(response);
        };
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("downloadFailures")
    public void extractListFromMetadata_downloadFailure_throws(String name, FailureSetup setup) throws Exception {
        URLConnectionHttpClient httpClient = mock(URLConnectionHttpClient.class);
        AttestationResponseHandler handler = mock(AttestationResponseHandler.class);
        when(handler.attested()).thenReturn(true);
        when(handler.getOptOutUrl()).thenReturn("https://optout.example");
        setup.apply(httpClient, handler);

        UidOptOutClient client = new UidOptOutClient("token", null, handler, httpClient, mock(UidInstanceIdProvider.class));
        OptOutCloudStorage storage = new OptOutCloudStorage(client, "/optout/refresh");

        assertThrows(CloudStorageException.class, storage::extractListFromMetadata);
    }

    private static JsonObject optOutSyncConfig(Path dataDir) {
        return new JsonObject()
                .put("optout_s3_folder", "optout/")
                .put("optout_data_dir", dataDir.toString())
                .put("optout_delta_rotate_interval", 300)
                .put("optout_delta_backtrack_in_days", 1)
                .put("optout_partition_interval", 86400)
                .put("optout_max_partitions", 30)
                .put("optout_producer_max_replicas", 1);
    }

    @Test
    public void refresh_downloadFailure_keepsLocalCache(@TempDir Path dataDir) throws CloudStorageException {
        OptOutCloudSync cloudSync = new OptOutCloudSync(optOutSyncConfig(dataDir), false);
        MemCachedStorage local = new MemCachedStorage();
        String delta = cloudSync.toLocalPath(OptOutUtils.newDeltaFileName(Instant.now()));
        String partition = cloudSync.toLocalPath(OptOutUtils.newPartitionFileName(Instant.now()));
        local.upload(new ByteArrayInputStream(new byte[0]), delta);
        local.upload(new ByteArrayInputStream(new byte[0]), partition);
        when(uidOptOutClient.download(anyString())).thenAnswer(i -> InputStream.nullInputStream());

        assertThrows(CloudStorageException.class, () -> cloudSync.refresh(Instant.now(), optOutCloudStorage, local,
                downloads -> {},
                deletes -> fail("deletes must not be called")));
        assertEquals(List.of(delta, partition).stream().sorted().toList(), local.list(dataDir.toString()).stream().sorted().toList());
    }

    @Nested
    @ExtendWith(VertxExtension.class)
    class CloudSyncVerticleTest {
        private final String storeName = "optout-test-" + UUID.randomUUID();
        private final SimpleMeterRegistry registry = new SimpleMeterRegistry();
        private HealthManager originalHealthManager;

        @BeforeEach
        void setUp() {
            originalHealthManager = HealthManager.instance;
            HealthManager.instance = new HealthManager();
            Metrics.globalRegistry.add(registry);
        }

        @AfterEach
        void tearDown() {
            Metrics.globalRegistry.remove(registry);
            HealthManager.instance = originalHealthManager;
        }

        private CloudSyncVerticle createVerticle(Path dataDir) {
            return new CloudSyncVerticle(storeName, optOutCloudStorage, new MemCachedStorage(),
                    new OptOutCloudSync(optOutSyncConfig(dataDir), false), 1, 1);
        }

        @Test
        void downloadFailureAtStartup_failsDeployAndIsUnhealthy(Vertx vertx, VertxTestContext testContext, @TempDir Path dataDir) throws Exception {
            when(uidOptOutClient.download(anyString())).thenAnswer(i -> InputStream.nullInputStream());

            vertx.deployVerticle(createVerticle(dataDir)).onComplete(testContext.failing(e -> testContext.verify(() -> {
                assertTrue(e.getMessage().contains("E12: Data Download Failure"));
                assertFalse(HealthManager.instance.isHealthy());
                assertTrue(HealthManager.instance.reason().contains("E12: Data Download Failure"));
                testContext.completeNow();
            })));
        }

        @Test
        void downloadFailureWhileRunning_setsConsecutiveFailureGaugeAndStaysHealthy(Vertx vertx, VertxTestContext testContext, @TempDir Path dataDir) throws Exception {
            AtomicBoolean failing = new AtomicBoolean(false);
            when(uidOptOutClient.download(anyString())).thenAnswer(i -> failing.get()
                    ? InputStream.nullInputStream()
                    : new ByteArrayInputStream(EMPTY_METADATA.getBytes()));
            CloudSyncVerticle verticle = createVerticle(dataDir);

            vertx.deployVerticle(verticle).onComplete(testContext.succeeding(id -> {
                failing.set(true);
                vertx.eventBus().publish(verticle.eventRefresh(), 0);
                vertx.setPeriodic(10, timerId -> testContext.verify(() -> {
                    double failures = registry.get("uid2_cloud_downloaded_consecutive_refresh_failures").tag("store", storeName).gauge().value();
                    if (failures == 1.0) {
                        vertx.cancelTimer(timerId);
                        assertTrue(HealthManager.instance.isHealthy());
                        testContext.completeNow();
                    }
                }));
            }));
        }
    }
}
