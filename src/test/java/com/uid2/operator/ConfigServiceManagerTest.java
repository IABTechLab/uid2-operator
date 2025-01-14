package com.uid2.operator;

import com.uid2.operator.service.ConfigServiceManager;
import com.uid2.operator.service.IConfigService;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.junit5.VertxExtension;
import io.vertx.junit5.VertxTestContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import static com.uid2.operator.Const.Config.*;
import static org.junit.jupiter.api.Assertions.*;
import static com.uid2.operator.service.UIDOperatorService.*;
import static org.mockito.Mockito.*;

@ExtendWith(VertxExtension.class)
public class ConfigServiceManagerTest {
    private JsonObject bootstrapConfig;
    private JsonObject staticConfig;
    private ConfigServiceManager configServiceManager;

    @BeforeEach
    void setUp(Vertx vertx) {
        bootstrapConfig = new JsonObject()
                .put(CoreConfigPath, "/operator/config")
                .put(ConfigScanPeriodMs, 300000)
                .put(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS, 3600)
                .put(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS, 7200)
                .put(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS, 1800)
                .put(MaxBidstreamLifetimeSecondsProp, 7200);
        staticConfig = new JsonObject(bootstrapConfig.toString())
                .put(MaxBidstreamLifetimeSecondsProp, 7201);

        IConfigService dynamicConfigService = mock(IConfigService.class);
        when(dynamicConfigService.getConfig()).thenReturn(bootstrapConfig);
        IConfigService staticConfigService = mock(IConfigService.class);
        when(staticConfigService.getConfig()).thenReturn(staticConfig);

        configServiceManager = new ConfigServiceManager(vertx, dynamicConfigService, staticConfigService, true);
    }

    @Test
    void testRemoteFeatureFlag(VertxTestContext testContext) {
        IConfigService delegatingConfigService = configServiceManager.getDelegatingConfigService();

        configServiceManager.updateConfigService(true)
                .compose(updateToDynamic -> {
                    testContext.verify(() -> assertEquals(bootstrapConfig, delegatingConfigService.getConfig()));

                    return configServiceManager.updateConfigService(false);
                })
                .onSuccess(updateToStatic -> testContext.verify(() -> {
                    assertEquals(staticConfig, delegatingConfigService.getConfig());
                    testContext.completeNow();
                }))
                .onFailure(testContext::failNow);
    }
}
