package com.uid2.operator;

import com.uid2.operator.service.ConfigService;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.config.ConfigRetriever;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.handler.BodyHandler;
import org.junit.jupiter.api.*;
import io.vertx.junit5.VertxExtension;
import io.vertx.junit5.VertxTestContext;
import org.junit.jupiter.api.extension.ExtendWith;

import java.lang.reflect.*;
import java.util.concurrent.TimeUnit;

import static com.uid2.operator.Const.Config.*;
import static com.uid2.operator.service.UIDOperatorService.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(VertxExtension.class)
class ConfigServiceTest {
    private Vertx vertx;
    private JsonObject bootstrapConfig;

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
    }

    @AfterEach
    void tearDown() {
        vertx.close();
    }

    void startMockServer(VertxTestContext testContext, JsonObject config) throws InterruptedException {
        Router router = Router.router(vertx);
        router.route().handler(BodyHandler.create());
        router.get("/config").handler(ctx -> ctx.response()
                .putHeader("content-type", "application/json")
                .end(config.encode()));

        vertx.createHttpServer()
                .requestHandler(router)
                .listen(Const.Port.ServicePortForCore,"127.0.0.1", http -> {
                    if (!http.succeeded()) {
                        testContext.failNow(http.cause());
                    }
                });

        testContext.awaitCompletion(5, TimeUnit.SECONDS);
    }

    @Test
    void testSingletonBehavior() {
        ConfigService instance1 = ConfigService.getInstance(vertx, bootstrapConfig);
        ConfigService instance2 = ConfigService.getInstance(vertx, bootstrapConfig);
        assertSame(instance1, instance2, "getInstance should return the same instance");
    }

    @Test
    void testGetConfig() {
        ConfigRetriever mockConfigRetriever = mock(ConfigRetriever.class);
        JsonObject cachedConfig = new JsonObject().put("key", "value");
        when(mockConfigRetriever.getCachedConfig()).thenReturn(cachedConfig);
        ConfigService configService = ConfigService.getInstance(vertx, bootstrapConfig);
        // Reflection to inject mocked ConfigRetriever
        try {
            Field configRetrieverField = ConfigService.class.getDeclaredField("configRetriever");
            configRetrieverField.setAccessible(true);
            configRetrieverField.set(configService, mockConfigRetriever);
        } catch (Exception e) {
            fail("Failed to inject mock ConfigRetriever: " + e.getMessage());
        }
        JsonObject result = configService.getConfig();
        assertEquals(cachedConfig, result, "getConfig should return the cached configuration");
    }

    @Test
    void testInitialiseConfigRetriever(VertxTestContext testContext) throws InterruptedException {
        JsonObject httpStoreConfig = new JsonObject().put("http", "value");
        this.startMockServer(testContext, httpStoreConfig);
        ConfigService configService = ConfigService.getInstance(vertx, bootstrapConfig);
        // Wait for the initialisation to finish - alternative is to have getInstance return a future
        testContext.awaitCompletion(1, TimeUnit.SECONDS);
        JsonObject retrievedConfig = configService.getConfig();
        assertNotNull(retrievedConfig, "Config retriever should initialise without error");
        assertTrue(retrievedConfig.fieldNames().containsAll(bootstrapConfig.fieldNames()), "Retrieved config should contain all keys in bootstrap config");
        assertTrue(retrievedConfig.fieldNames().containsAll(httpStoreConfig.fieldNames()), "Retrieved config should contain all keys in http store config");
        testContext.completeNow();
    }

    @Test
    void testInvalidConfigRevertsToPrevious() {
        ConfigRetriever mockConfigRetriever = mock(ConfigRetriever.class);
        JsonObject lastConfig = new JsonObject().put("previous", "config");
        JsonObject invalidConfig = new JsonObject()
                .put(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS, 1000)
                .put(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS, 2000);
        when(mockConfigRetriever.getCachedConfig()).thenReturn(lastConfig);
        ConfigService configService = ConfigService.getInstance(vertx, bootstrapConfig);
        try {
            Field configRetrieverField = ConfigService.class.getDeclaredField("configRetriever");
            configRetrieverField.setAccessible(true);
            configRetrieverField.set(configService, mockConfigRetriever);
        } catch (Exception e) {
            fail("Failed to inject mock ConfigRetriever: " + e.getMessage());
        }

        try {
            Method configValidationHandlerMethod = ConfigService.class.getDeclaredMethod("configValidationHandler", JsonObject.class);
            configValidationHandlerMethod.setAccessible(true);
            JsonObject validatedConfig = (JsonObject) configValidationHandlerMethod.invoke(configService, invalidConfig);
            assertEquals(lastConfig, validatedConfig, "Invalid config not reverted to previous config");
        } catch (Exception e) {
            fail("Failed to access and invoke the configValidationHandler method: " + e.getMessage());
        }
    }

    @Test
    void testFirstInvalidConfigThrowsRuntimeException() {
        ConfigRetriever mockConfigRetriever = mock(ConfigRetriever.class);
        JsonObject invalidConfig = new JsonObject()
                .put(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS, 1000)
                .put(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS, 2000);
        when(mockConfigRetriever.getCachedConfig()).thenReturn(null);
        ConfigService configService = ConfigService.getInstance(vertx, bootstrapConfig);
        try {
            Field configRetrieverField = ConfigService.class.getDeclaredField("configRetriever");
            configRetrieverField.setAccessible(true);
            configRetrieverField.set(configService, mockConfigRetriever);
        } catch (Exception e) {
            fail("Failed to inject mock ConfigRetriever: " + e.getMessage());
        }



        try {
            Method configValidationHandlerMethod = ConfigService.class.getDeclaredMethod("configValidationHandler", JsonObject.class);
            configValidationHandlerMethod.setAccessible(true);
            assertThrows(RuntimeException.class, () -> {
                try {
                    configValidationHandlerMethod.invoke(configService, invalidConfig);
                } catch (InvocationTargetException e) {
                    // Throw cause as InvocationTargetException wraps actual exception thrown by configValidationHandler
                    throw e.getCause();
                }
            });
        } catch (Exception e) {
            fail("Failed to access and invoke the configValidationHandler method: " + e.getMessage());
        }
    }
}