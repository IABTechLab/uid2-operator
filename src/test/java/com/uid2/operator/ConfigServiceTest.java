package com.uid2.operator;

import com.uid2.operator.service.ConfigRetrieverFactory;
import com.uid2.operator.service.ConfigService;
import io.vertx.core.Vertx;
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
    private ConfigRetriever configRetriever;
    private HttpServer server;

    @BeforeEach
    void setUp() {
        vertx = Vertx.vertx();
        bootstrapConfig = new JsonObject()
                .put(CoreConfigPath, "/config")
                .put(ConfigScanPeriodMs, 300000)
                .put(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS, 3600)
                .put(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS, 7200)
                .put(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS, 1800)
                .put(MaxBidstreamLifetimeSecondsProp, 7200);

        ConfigRetrieverFactory configRetrieverFactory = new ConfigRetrieverFactory();
        configRetriever = configRetrieverFactory.create(vertx, bootstrapConfig);
    }

    @AfterEach
    void tearDown() {
        vertx.close();
    }

    void startMockServer(VertxTestContext testContext, JsonObject config) {
        if (server != null) {
            server.close();
        }

        Router router = Router.router(vertx);
        router.route().handler(BodyHandler.create());
        router.get("/config").handler(ctx -> ctx.response()
                .putHeader("content-type", "application/json")
                .end(config.encode()));

        server = vertx.createHttpServer()
                .requestHandler(router)
                .listen(Const.Port.ServicePortForCore,"127.0.0.1", http -> {
                    if (!http.succeeded()) {
                        testContext.failNow(http.cause());
                    }
                });
    }

    @Test
    void testGetConfig(VertxTestContext testContext) {
        JsonObject httpStoreConfig = new JsonObject().put("http", "value");
        this.startMockServer(testContext, httpStoreConfig);
        ConfigService.create(configRetriever).onComplete(ar -> {
            if (ar.succeeded()) {
                ConfigService configService = ar.result();
                JsonObject retrievedConfig = configService.getConfig();
                assertNotNull(retrievedConfig, "Config retriever should initialise without error");
                assertTrue(retrievedConfig.fieldNames().containsAll(bootstrapConfig.fieldNames()), "Retrieved config should contain all keys in bootstrap config");
                assertTrue(retrievedConfig.fieldNames().containsAll(httpStoreConfig.fieldNames()), "Retrieved config should contain all keys in http store config");
                testContext.completeNow();
            } else {
                testContext.failNow(ar.cause());
            }
        });

    }

    @Test
    void testInvalidConfigRevertsToPrevious(VertxTestContext testContext) {
        JsonObject lastConfig = new JsonObject().put("previous", "config");
        ConfigRetriever spyRetriever = spy(configRetriever);
        when(spyRetriever.getCachedConfig()).thenReturn(lastConfig);
        JsonObject invalidConfig = new JsonObject()
                .put(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS, 1000)
                .put(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS, 2000);
        this.startMockServer(testContext, invalidConfig);
        ConfigService.create(spyRetriever).onComplete(ar -> {
           if (ar.succeeded()) {
               reset(spyRetriever);
               ConfigService configService = ar.result();
               assertEquals(lastConfig, configService.getConfig(), "Invalid config not reverted to previous config");
               testContext.completeNow();
           }
           else {
               testContext.failNow(ar.cause());
           }
        });
    }

    @Test
    void testFirstInvalidConfigThrowsRuntimeException(VertxTestContext testContext) {
        JsonObject invalidConfig = new JsonObject()
                .put(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS, 1000)
                .put(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS, 2000);
        this.startMockServer(testContext, invalidConfig);
        ConfigService.create(configRetriever).onComplete(ar -> {
            if (ar.succeeded()) {
                testContext.failNow(new RuntimeException("Expected a RuntimeException but the creation succeeded"));
            }
            else {
                assertThrows(RuntimeException.class, () -> {
                    throw ar.cause();
                });
                testContext.completeNow();
            }
        });
    }
}