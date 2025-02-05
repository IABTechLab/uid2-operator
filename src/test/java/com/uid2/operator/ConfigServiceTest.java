package com.uid2.operator;

import com.uid2.operator.service.ConfigRetrieverFactory;
import com.uid2.operator.service.ConfigService;
import com.uid2.shared.health.HealthManager;
import io.vertx.core.*;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonObject;
import io.vertx.config.ConfigRetriever;
import io.vertx.core.streams.ReadStream;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.BodyHandler;
import org.junit.jupiter.api.*;
import io.vertx.junit5.VertxExtension;
import io.vertx.junit5.VertxTestContext;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;

import static com.uid2.operator.Const.Config.*;
import static com.uid2.operator.service.UIDOperatorService.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(VertxExtension.class)
class ConfigServiceTest {
    private Vertx vertx;
    private JsonObject bootstrapConfig;
    private JsonObject runtimeConfig;
    private HttpServer server;
    private ConfigRetrieverFactory configRetrieverFactory;

    @BeforeEach
    void setUp() {
        vertx = Vertx.vertx();
        bootstrapConfig = new JsonObject()
                .put("type", "http")
                .put("config", new JsonObject()
                        .put("host", "localhost")
                        .put("port", 8088)
                        .put("path", "/operator/config"))
                .put(ConfigScanPeriodMs, 300000);

        runtimeConfig = new JsonObject()
                .put(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS, 3600)
                .put(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS, 7200)
                .put(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS, 1800)
                .put(MaxBidstreamLifetimeSecondsProp, 7200);

        configRetrieverFactory = new ConfigRetrieverFactory();

    }

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.close();
        }
        vertx.close();
    }

    private Future<Void> startMockServer(JsonObject config) {
        Promise<Void> promise = Promise.promise();

        Future<Void> closeFuture = Future.succeededFuture();
        if (server != null) {
            closeFuture = server.close();
        }

        closeFuture.onComplete(ar -> {
            if (ar.succeeded()) {
                Router router = Router.router(vertx);
                router.route().handler(BodyHandler.create());
                router.get("/operator/config").handler(ctx -> ctx.response()
                        .putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                        .end(config.encode()));

                server = vertx.createHttpServer()
                        .requestHandler(router)
                        .listen(Const.Port.ServicePortForCore, "127.0.0.1", http -> {
                            if (http.succeeded()) {
                                promise.complete();
                            } else {
                                promise.fail(http.cause());
                            }
                        });
            } else {
                promise.fail(ar.cause());
            }
        });

        return promise.future();
    }

    @Test
    void testGetConfig(VertxTestContext testContext) {
        ConfigRetriever configRetriever = configRetrieverFactory.create(vertx, bootstrapConfig, "");
        JsonObject httpStoreConfig = runtimeConfig;
        startMockServer(httpStoreConfig)
                .compose(v -> ConfigService.create(configRetriever))
                .compose(configService -> {
                    JsonObject retrievedConfig = configService.getConfig();
                    assertNotNull(retrievedConfig, "Config retriever should initialise without error");
                    assertTrue(retrievedConfig.fieldNames().containsAll(httpStoreConfig.fieldNames()), "Retrieved config should contain all keys in http store config");
                    return Future.succeededFuture();
                })
                .onComplete(testContext.succeedingThenComplete());
    }

    @Test
    void testInvalidConfigRevertsToPrevious(VertxTestContext testContext) {
        JsonObject lastConfig = new JsonObject().put("previous", "config");
        JsonObject invalidConfig = new JsonObject()
                .put(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS, 1000)
                .put(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS, 2000);
        JsonObject jsonBootstrapConfig = new JsonObject()
                .put("type", "json")
                .put("config", invalidConfig)
                .put(ConfigScanPeriodMs, -1);
        ConfigRetriever spyRetriever = spy(configRetrieverFactory.create(vertx, jsonBootstrapConfig, ""));
        when(spyRetriever.getCachedConfig()).thenReturn(lastConfig);
        ConfigService.create(spyRetriever)
                .compose(configService -> {
                    reset(spyRetriever);
                    assertEquals(lastConfig, configService.getConfig(), "Invalid config not reverted to previous config");
                    return Future.succeededFuture();
                })
                .onComplete(testContext.succeedingThenComplete());
    }

    @Test
    void testFirstInvalidConfigThrowsRuntimeException(VertxTestContext testContext) {
        JsonObject invalidConfig = new JsonObject()
                .put(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS, 1000)
                .put(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS, 2000);
        JsonObject jsonBootstrapConfig = new JsonObject()
                .put("type", "json")
                .put("config", invalidConfig)
                .put(ConfigScanPeriodMs, -1);
        ConfigRetriever configRetriever = configRetrieverFactory.create(vertx, jsonBootstrapConfig, "");
        ConfigService.create(configRetriever)
                .onComplete(testContext.failing(throwable -> {
                   assertThrows(RuntimeException.class, () -> {
                       throw throwable;
                   }, "Expected a RuntimeException but the creation succeeded");
                   testContext.completeNow();
                }));
    }

    @Test
    public void testConfigStreamExceptionHandler(VertxTestContext testContext) {
        JsonObject jsonBootstrapConfig = new JsonObject()
                .put("type", "json")
                .put("config", runtimeConfig)
                .put(ConfigScanPeriodMs, -1);

        ConfigRetriever mockRetriever = spy(configRetrieverFactory.create(vertx, jsonBootstrapConfig, ""));
        ReadStream<JsonObject> mockStream = mock(ReadStream.class);

        when(mockRetriever.configStream()).thenReturn(mockStream);

        ArgumentCaptor<Handler<Throwable>> exceptionHandlerCaptor =
                ArgumentCaptor.forClass(Handler.class);
        doReturn(mockStream).when(mockStream).exceptionHandler(exceptionHandlerCaptor.capture());

        ConfigService.create(mockRetriever)
                .onComplete(testContext.succeeding( configService -> {
                    testContext.verify(() -> {
                    assertTrue(HealthManager.instance.isHealthy(), "ConfigService should be healthy after successful initialisation");
                    RuntimeException simulatedException = new RuntimeException("Test Exception");
                    Handler<Throwable> capturedHandler = exceptionHandlerCaptor.getValue();
                    for (int i = 0; i < ConfigService.MAX_FAILURE_COUNT; i++) {
                        capturedHandler.handle(simulatedException);
                    }
                    assertFalse(HealthManager.instance.isHealthy(), "ConfigService should be unhealthy after " + ConfigService.MAX_FAILURE_COUNT + " failed retrievals");
                    });
                    testContext.completeNow();
                }));
    }
}