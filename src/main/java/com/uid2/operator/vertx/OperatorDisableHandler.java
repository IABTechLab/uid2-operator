package com.uid2.operator.vertx;

import com.uid2.operator.Main;
import io.vertx.core.Handler;
import io.vertx.ext.web.RoutingContext;
import lombok.extern.java.Log;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.utils.Pair;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

public class OperatorDisableHandler{
    private static final Logger LOGGER = LoggerFactory.getLogger(OperatorDisableHandler.class);
    private Duration shutdownWaitTime = Duration.ofSeconds(10);
    private AtomicReference<Instant> failureStartTime = new AtomicReference<>(null);
    private final Clock clock;

    public OperatorDisableHandler(Duration shutdownWaitTime, Clock clock) {
        this.shutdownWaitTime = shutdownWaitTime;
        this.clock = clock;
    }


    public void handleResponse(Pair<Integer, String> response) {
        if (response.right().equals("Unauthorized")) {
            LOGGER.error("core attestation failed due to invalid key. shutting down operator");
            System.exit(1);
        }
        switch (response.left()) {
            case 200:
                failureStartTime.set(null);
                break;
            default:
                Instant t = failureStartTime.get();
                if (t == null) {
                    failureStartTime.set(clock.instant());
                } else if (Duration.between(t, clock.instant()).compareTo(this.shutdownWaitTime) > 0) {

                }
        }
    }
}
