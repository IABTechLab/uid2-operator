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
    private final IConfigService staticConfigService;
    private static final Logger logger = LoggerFactory.getLogger(ConfigServiceManager.class);

    public ConfigServiceManager(Vertx vertx, IConfigService staticConfigService, boolean useDynamicConfig) {
        this.vertx = vertx;
        this.staticConfigService = staticConfigService;
        this.delegatingConfigService = new DelegatingConfigService(staticConfigService);
    }

    public Future<Void> updateConfigService(boolean useDynamicConfig) {
        Promise<Void> promise = Promise.promise();
        vertx.sharedData().getLocalLock("updateConfigServiceLock", lockAsyncResult -> {
            if (lockAsyncResult.succeeded()) {
                Lock lock = lockAsyncResult.result();
                try {
                    /*if (useDynamicConfig) {
                        logger.info("Switching to DynamicConfigService");
                        delegatingConfigService.updateConfigService(dynamicConfigService);
                    } else {*/
                        logger.info("Switching to StaticConfigService");
                        delegatingConfigService.updateConfigService(staticConfigService);
//                    }
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
