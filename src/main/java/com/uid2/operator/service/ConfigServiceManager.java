package com.uid2.operator.service;

import io.vertx.core.Future;
import io.vertx.core.Promise;
import io.vertx.core.Vertx;
import io.vertx.core.shareddata.Lock;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ConfigServiceManager {
    private final Vertx vertx;
    private final DelegatingConfigService delegatingConfigService;
    private final IConfigService dynamicConfigService;
    private final IConfigService staticConfigService;
    private static final Logger logger = LoggerFactory.getLogger(ConfigServiceManager.class);

    public ConfigServiceManager(Vertx vertx, IConfigService dynamicConfigService, IConfigService staticConfigService, boolean remoteConfigEnabled) {
        this.vertx = vertx;
        this.dynamicConfigService = dynamicConfigService;
        this.staticConfigService = staticConfigService;
        this.delegatingConfigService = new DelegatingConfigService(remoteConfigEnabled ? dynamicConfigService : staticConfigService);
    }

    public Future<Void> updateConfigService(boolean remoteConfigEnabled) {
        Promise<Void> promise = Promise.promise();
        vertx.sharedData().getLocalLock("updateConfigServiceLock", lockAsyncResult -> {
            if (lockAsyncResult.succeeded()) {
                Lock lock = lockAsyncResult.result();
                try {
                    if (remoteConfigEnabled) {
                        logger.info("Switching to DynamicConfigService");
                        delegatingConfigService.updateConfigService(dynamicConfigService);
                    } else {
                        logger.info("Switching to StaticConfigService");
                        delegatingConfigService.updateConfigService(staticConfigService);
                    }
                    promise.complete();
                } catch (Exception e) {
                    promise.fail(e);
                } finally {
                    lock.release();
                }
            } else {
                logger.error("Failed to acquire lock for updating active ConfigService", lockAsyncResult.cause());
                promise.fail(lockAsyncResult.cause());
            }
        });

        return promise.future();
    }

    public IConfigService getDelegatingConfigService() {
        return delegatingConfigService;
    }

}
