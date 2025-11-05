package com.uid2.operator.store;

import com.uid2.operator.Const;
import com.uid2.operator.model.IdentityScope;
import com.uid2.operator.model.IdentityType;
import com.uid2.operator.model.UserIdentity;
import com.uid2.operator.service.EncodingUtils;
import com.uid2.shared.cloud.MemCachedStorage;
import com.uid2.shared.audit.Audit;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.BodyHandler;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

public class CloudSyncOptOutStoreTest {
    private Vertx vertx;
    private HttpServer server;
    private int port;
    private Router router;

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
    void addEntry_sendsPostWithQueryAndJsonBody() throws Exception {
        final String path = "/optout/replicate";
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
        JsonObject config = new JsonObject()
                .put(Const.Config.OptOutApiUriProp, "http://localhost:" + port + path)
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

        CloudSyncOptOutStore store = new CloudSyncOptOutStore(vertx, new MemCachedStorage(), config, operatorKey, Clock.systemUTC());

        UserIdentity uid = new UserIdentity(IdentityScope.UID2, IdentityType.Email, userIdBytes, 0, Instant.now(), Instant.now());

        CountDownLatch done = new CountDownLatch(1);
        store.addEntry(uid, advIdBytes, uidTraceId, "local-instance", email, phone, clientIp, ar -> done.countDown());

        assertTrue(received.await(5, TimeUnit.SECONDS));
        assertTrue(done.await(5, TimeUnit.SECONDS));
    }
}
