package com.uid2.operator.vertx;

import com.uid2.operator.Const;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

public class OperatorDisableHandler implements Handler<RoutingContext> {
    private JsonObject config;
    private AtomicReference<Boolean> canServe = new AtomicReference<>(true);
    private AtomicReference<Instant> failureStartTime = new AtomicReference<>(null);
    private final Clock clock;

    public OperatorDisableHandler(JsonObject config, Clock clock) {
        this.config = config;
        this.clock = clock;
    }

    @Override
    public void handle(RoutingContext rc) {
        if (canServe.get()) {
            rc.next();
        } else {
            rc.fail(503);
        }
    }

    public void handleResponseStatus(Integer statusCode) {
        switch (statusCode.intValue()) {
            case 200:
                canServe.set(Boolean.TRUE);
                failureStartTime.set(null);
                break;

            case 401:
                canServe.set(Boolean.FALSE);
                break;

            default:
                Instant t = failureStartTime.get();
                if (t == null) {
                    failureStartTime.set(clock.instant());
                } else {
                    if (Duration.between(t, clock.instant()).toHours() >= this.config.getInteger(Const.Config.FailureShutdownWaitHoursProp, 120)) {
                        canServe.set(Boolean.FALSE);
                    }
                }
        }
    }
}
