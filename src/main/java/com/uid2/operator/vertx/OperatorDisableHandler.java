package com.uid2.operator.vertx;

import com.uid2.operator.Const;
import io.vertx.core.Handler;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

public class OperatorDisableHandler implements Handler<RoutingContext> {
    private Duration disableWaitTime;
    private AtomicBoolean canServe = new AtomicBoolean(true);
    private AtomicReference<Instant> failureStartTime = new AtomicReference<>(null);
    private final Clock clock;

    public OperatorDisableHandler(Duration disableWaitTime, Clock clock) {
        this.disableWaitTime = disableWaitTime;
        this.clock = clock;
    }

    @Override
    public void handle(RoutingContext ctx) {
        if (canServe.get()) {
            ctx.next();
        } else {
            ctx.fail(503);
        }
    }

    public void handleResponseStatus(Integer statusCode) {
        switch (statusCode.intValue()) {
            case 200:
                canServe.set(true);
                failureStartTime.set(null);
                break;

            case 401:
                canServe.set(false);
                break;

            default:
                Instant t = failureStartTime.get();
                if (t == null) {
                    failureStartTime.set(clock.instant());
                } else if (Duration.between(t, clock.instant()).compareTo(this.disableWaitTime) > 0) {
                    canServe.set(false);
                }
        }
    }
}
