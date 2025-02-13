package com.uid2.operator;

import com.uid2.operator.service.ConfigRetrieverFactory;
import com.uid2.operator.service.ConfigService;
import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.config.ConfigRetriever;
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
    private JsonObject runtimeConfig;
    private JsonObject invalidBootstrapConfig;

    @BeforeEach
    void setUp() {
        vertx = Vertx.vertx();

        runtimeConfig = new JsonObject()
                .put(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS, 3600)
                .put(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS, 7200)
                .put(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS, 1800)
                .put(MaxBidstreamLifetimeSecondsProp, 7200)
                .put(SharingTokenExpiryProp, 3600);

        JsonObject invalidConfig = new JsonObject()
                .put(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS, 1000)
                .put(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS, 2000);

        bootstrapConfig = new JsonObject()
                .put("type", "json")
                .put("config", runtimeConfig);

        invalidBootstrapConfig = new JsonObject()
                .put("type", "json")
                .put("config", invalidConfig);
    }

    @AfterEach
    void tearDown() {
        vertx.close();
    }

    @Test
    void testGetConfig(VertxTestContext testContext) {
        ConfigRetriever configRetriever = ConfigRetrieverFactory.create(vertx, bootstrapConfig);
        ConfigService.create(configRetriever)
                .compose(configService -> {
                    JsonObject retrievedConfig = configService.getConfig();
                    assertNotNull(retrievedConfig, "Config retriever should initialise without error");
                    assertTrue(retrievedConfig.fieldNames().containsAll(runtimeConfig.fieldNames()), "Retrieved config should contain all keys in runtime config");
                    return Future.succeededFuture();
                })
                .onComplete(testContext.succeedingThenComplete());
    }

    @Test
    void testInvalidConfigRevertsToPrevious(VertxTestContext testContext) {
        JsonObject lastConfig = new JsonObject().put("previous", "config");
        ConfigRetriever spyRetriever = spy(ConfigRetrieverFactory.create(vertx, invalidBootstrapConfig));
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
        ConfigRetriever configRetriever = ConfigRetrieverFactory.create(vertx, invalidBootstrapConfig);
        ConfigService.create(configRetriever)
                .onComplete(testContext.failing(throwable -> {
                   assertThrows(RuntimeException.class, () -> {
                       throw throwable;
                   }, "Expected a RuntimeException but the creation succeeded");
                   testContext.completeNow();
                }));
    }
}