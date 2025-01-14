package com.uid2.operator;

import com.uid2.operator.service.ConfigRetrieverFactory;
import com.uid2.operator.service.ConfigService;
import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.HttpServer;
import io.vertx.core.json.JsonObject;
import io.vertx.config.ConfigRetriever;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.BodyHandler;
import org.junit.jupiter.api.*;
import io.vertx.junit5.VertxExtension;
import io.vertx.junit5.VertxTestContext;
import org.junit.jupiter.api.extension.ExtendWith;

import static com.uid2.operator.Const.Config.*;
import static com.uid2.operator.service.UIDOperatorService.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(VertxExtension.class)
class ConfigServiceTest {
    private Vertx vertx;
    private JsonObject bootstrapConfig;
    private HttpServer server;
    private ConfigRetrieverFactory configRetrieverFactory;

    @BeforeEach
    void setUp() {
        vertx = Vertx.vertx();
        bootstrapConfig = new JsonObject()
                .put(CoreConfigPath, "/operator/config")
                .put(ConfigScanPeriodMs, 300000)
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
        if (server != null) {
            server.close();
        }

        Promise<Void> promise = Promise.promise();

        Router router = Router.router(vertx);
        router.route().handler(BodyHandler.create());
        router.get("/operator/config").handler(ctx -> ctx.response()
                .putHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                .end(config.encode()));

        server = vertx.createHttpServer()
                .requestHandler(router)
                .listen(Const.Port.ServicePortForCore,"127.0.0.1", http -> {
                    if (http.succeeded()) {
                        promise.complete();
                    } else {
                        promise.fail(http.cause());
                    }
                });

        return promise.future();
    }

    @Test
    void testGetConfig(VertxTestContext testContext) {
        ConfigRetriever configRetriever = configRetrieverFactory.createHttpRetriever(vertx, bootstrapConfig);
        JsonObject httpStoreConfig = bootstrapConfig;
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
        ConfigRetriever spyRetriever = spy(configRetrieverFactory.createJsonRetriever(vertx, invalidConfig));
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
        ConfigRetriever configRetriever = configRetrieverFactory.createJsonRetriever(vertx, invalidConfig);
        ConfigService.create(configRetriever)
                .onComplete(testContext.failing(throwable -> {
                   assertThrows(RuntimeException.class, () -> {
                       throw throwable;
                   }, "Expected a RuntimeException but the creation succeeded");
                   testContext.completeNow();
                }));
    }
}