package com.uid2.operator.store;

import com.uid2.operator.Const;
import com.uid2.operator.model.IdentityScope;
import com.uid2.operator.model.IdentityType;
import com.uid2.operator.model.UserIdentity;
import com.uid2.operator.service.EncodingUtils;
import com.uid2.shared.cloud.MemCachedStorage;
import com.uid2.shared.audit.Audit;
import io.vertx.core.AsyncResult;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.BodyHandler;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.*;

public class CloudSyncOptOutStoreTest {
    private Vertx vertx;
    private HttpServer server;
    private int port;
    private Router router;

    private static final String PATH = "/optout/replicate";
    private static final String CONFIGURED_API_URI = "https://configured.example.invalid" + PATH;

    @BeforeEach
    void setUp() throws InterruptedException {
        vertx = Vertx.vertx();
        CountDownLatch latch = new CountDownLatch(1);
        server = vertx.createHttpServer();
        router = Router.router(vertx);
        router.route().handler(BodyHandler.create());
        server.requestHandler(router);
        server.listen(0, ar -> {
            if (ar.succeeded()) {
                port = ar.result().actualPort();
                latch.countDown();
            }
        });
        assertTrue(latch.await(5, TimeUnit.SECONDS));
    }

    @AfterEach
    void tearDown() throws InterruptedException {
        CountDownLatch latch = new CountDownLatch(1);
        server.close(ar -> latch.countDown());
        assertTrue(latch.await(5, TimeUnit.SECONDS));
        CountDownLatch latch2 = new CountDownLatch(1);
        vertx.close(ar -> latch2.countDown());
        assertTrue(latch2.await(5, TimeUnit.SECONDS));
    }

    @Test
    void addEntry_sendsPostToOptOutBaseUrlHostWithQueryAndJsonBody() throws Exception {
        final String path = PATH;
        final String operatorKey = "test-operator-key";
        final String uidTraceId = "trace-123";
        final String email = "post@test.com";
        final String phone = null;
        final String clientIp = "203.0.113.5";

        final byte[] userIdBytes = new byte[] {10, 20, 30};
        final byte[] advIdBytes = new byte[] {1, 2, 3};
        final String expectedIdentityHash = EncodingUtils.toBase64String(userIdBytes);
        final String expectedAdvertisingId = EncodingUtils.toBase64String(advIdBytes);

        CountDownLatch received = new CountDownLatch(1);

        router.post(path).handler(ctx -> {
            try {
                assertEquals(HttpMethod.POST, ctx.request().method());
                assertEquals(path, ctx.normalisedPath());
                assertEquals(expectedIdentityHash, ctx.request().getParam("identity_hash"));
                assertEquals(expectedAdvertisingId, ctx.request().getParam("advertising_id"));
                assertEquals("Bearer " + operatorKey, ctx.request().getHeader("Authorization"));
                assertEquals(uidTraceId, ctx.request().getHeader(Audit.UID_TRACE_ID_HEADER));

                JsonObject body = ctx.body().asJsonObject();
                assertNotNull(body);
                assertEquals(email, body.getString("email"));
                assertEquals(clientIp, body.getString("client_ip"));
                assertFalse(body.containsKey("unexpected"));

                ctx.response().setStatusCode(200).end();
            } finally {
                received.countDown();
            }
        });
        CloudSyncOptOutStore store = createStore(operatorKey, () -> "http://localhost:" + port);

        UserIdentity uid = new UserIdentity(IdentityScope.UID2, IdentityType.Email, userIdBytes, 0, Instant.now(), Instant.now());

        CountDownLatch done = new CountDownLatch(1);
        store.addEntry(uid, advIdBytes, uidTraceId, "local-instance", email, phone, clientIp, ar -> done.countDown());

        assertTrue(received.await(5, TimeUnit.SECONDS));
        assertTrue(done.await(5, TimeUnit.SECONDS));
    }

    @Test
    void addEntry_readsOptOutBaseUrlOnEachCall() throws Exception {
        List<String> hosts = Collections.synchronizedList(new ArrayList<>());
        router.post(PATH).handler(ctx -> {
            hosts.add(ctx.request().getHeader("Host"));
            ctx.response().setStatusCode(200).end();
        });
        AtomicReference<String> baseUrl = new AtomicReference<>("http://localhost:" + port);
        CloudSyncOptOutStore store = createStore("key", baseUrl::get);

        assertTrue(addEntry(store).succeeded());
        baseUrl.set("http://127.0.0.1:" + port);
        assertTrue(addEntry(store).succeeded());

        assertEquals(List.of("localhost:" + port, "127.0.0.1:" + port), hosts);
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"nowhere"})
    void addEntry_failsWithoutRequestWhenOptOutBaseUrlUnusable(String optOutBaseUrl) throws Exception {
        List<String> requests = Collections.synchronizedList(new ArrayList<>());
        router.route().handler(ctx -> {
            requests.add(ctx.request().uri());
            ctx.response().setStatusCode(200).end();
        });
        CloudSyncOptOutStore store = createStore("key", () -> optOutBaseUrl);

        assertTrue(addEntry(store).failed());
        assertTrue(requests.isEmpty());
    }

    private AsyncResult<Instant> addEntry(CloudSyncOptOutStore store) throws InterruptedException {
        UserIdentity uid = new UserIdentity(IdentityScope.UID2, IdentityType.Email, new byte[] {1}, 0, Instant.now(), Instant.now());
        AtomicReference<AsyncResult<Instant>> result = new AtomicReference<>();
        CountDownLatch done = new CountDownLatch(1);
        store.addEntry(uid, new byte[] {2}, null, "local-instance", null, null, null, ar -> {
            result.set(ar);
            done.countDown();
        });
        assertTrue(done.await(5, TimeUnit.SECONDS));
        return result.get();
    }

    private CloudSyncOptOutStore createStore(String operatorKey, Supplier<String> optOutBaseUrl) throws Exception {
        JsonObject config = new JsonObject()
                .put(Const.Config.OptOutApiUriProp, CONFIGURED_API_URI)
                .put(Const.Config.OptOutBloomFilterSizeProp, 8192)
                .put(Const.Config.OptOutHeapDefaultCapacityProp, 8192)
                .put(Const.Config.OptOutStatusApiEnabled, true)
                .put(Const.Config.OptOutDataDirProp, "/tmp/uid2-operator-test")
                // Additional required config for FileUtils/optout snapshot
                .put("optout_delta_rotate_interval", 300)
                .put("optout_delta_backtrack_in_days", 1)
                .put("optout_partition_interval", 86400)
                .put("optout_max_partitions", 30)
                .put("optout_s3_folder", "optout/")
                .put("optout_s3_path_compat", false);

        return new CloudSyncOptOutStore(vertx, new MemCachedStorage(), config, operatorKey, optOutBaseUrl, Clock.systemUTC());
    }
}
