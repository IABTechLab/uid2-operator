package com.uid2.operator;

import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServer;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.BodyHandler;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

public class MainValidationTest {
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

    private String attestUrl() {
        return "http://localhost:" + port + "/attest";
    }

    @Test
    void validKeyPassesBothChecks() throws Exception {
        router.get("/ops/healthcheck").handler(rc -> rc.response().setStatusCode(200).end("OK"));
        router.get("/ops/operator_key_check").handler(rc -> {
            String auth = rc.request().getHeader("Authorization");
            if ("Bearer valid-key".equals(auth)) {
                rc.response().setStatusCode(200).end("{\"status\":\"ok\"}");
            } else {
                rc.response().setStatusCode(401).end();
            }
        });

        assertDoesNotThrow(() -> Main.validateCoreConnectivityAndOperatorKey(attestUrl(), "valid-key"));
    }

    @Test
    void invalidKeyThrowsWithClearMessage() {
        router.get("/ops/healthcheck").handler(rc -> rc.response().setStatusCode(200).end("OK"));
        router.get("/ops/operator_key_check").handler(rc -> rc.response().setStatusCode(401).end());

        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> Main.validateCoreConnectivityAndOperatorKey(attestUrl(), "wrong-key"));
        assertTrue(ex.getMessage().contains("invalid or not authorized"),
                "Error message should indicate key is invalid, got: " + ex.getMessage());
    }

    @Test
    void unreachableCoreThrowsWithClearMessage() {
        // Use a port that is not listening
        String badUrl = "http://localhost:1/attest";
        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> Main.validateCoreConnectivityAndOperatorKey(badUrl, "any-key"));
        assertTrue(ex.getMessage().contains("cannot connect") || ex.getMessage().contains("Cannot connect"),
                "Error message should mention connectivity failure, got: " + ex.getMessage());
    }

    @Test
    void unhealthyCoreThrowsWithClearMessage() {
        router.get("/ops/healthcheck").handler(rc -> rc.response().setStatusCode(503).end("Unhealthy"));

        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> Main.validateCoreConnectivityAndOperatorKey(attestUrl(), "any-key"));
        assertTrue(ex.getMessage().contains("HTTP 503"),
                "Error message should mention the HTTP status code, got: " + ex.getMessage());
    }

    @Test
    void missingKeyCheckEndpointLogsWarningAndContinues() throws Exception {
        router.get("/ops/healthcheck").handler(rc -> rc.response().setStatusCode(200).end("OK"));
        // /ops/operator_key_check returns 404 (endpoint not yet deployed on core)
        router.get("/ops/operator_key_check").handler(rc -> rc.response().setStatusCode(404).end());

        // Should NOT throw — backward compatible with older core deployments
        assertDoesNotThrow(() -> Main.validateCoreConnectivityAndOperatorKey(attestUrl(), "any-key"));
    }

    @Test
    void forbiddenKeyThrowsWithClearMessage() {
        router.get("/ops/healthcheck").handler(rc -> rc.response().setStatusCode(200).end("OK"));
        router.get("/ops/operator_key_check").handler(rc -> rc.response().setStatusCode(403).end());

        IllegalStateException ex = assertThrows(IllegalStateException.class,
                () -> Main.validateCoreConnectivityAndOperatorKey(attestUrl(), "forbidden-key"));
        assertTrue(ex.getMessage().contains("invalid or not authorized"),
                "Error message should indicate key is unauthorized, got: " + ex.getMessage());
    }
}
