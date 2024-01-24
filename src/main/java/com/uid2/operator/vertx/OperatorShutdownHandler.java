package com.uid2.operator.vertx;

import com.uid2.operator.service.ShutdownService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.utils.Pair;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;

public class OperatorShutdownHandler {
    private static final Logger LOGGER = LoggerFactory.getLogger(OperatorShutdownHandler.class);
    private final Duration shutdownWaitTime;
    private final AtomicReference<Instant> failureStartTime = new AtomicReference<>(null);
    private final Clock clock;
    private final ShutdownService shutdownService;

    public OperatorShutdownHandler(Duration shutdownWaitTime, Clock clock, ShutdownService shutdownService) {
        this.shutdownWaitTime = shutdownWaitTime;
        this.clock = clock;
        this.shutdownService = shutdownService;
    }


    public void handleResponse(Pair<Integer, String> response) {
        if (response.left() == 401) {
            LOGGER.error("core attestation failed with 401, shutting down operator, core response: " + response.right());
            this.shutdownService.Shutdown(1);
        }
        if (response.left() == 200) {
            failureStartTime.set(null);
        } else {
            Instant t = failureStartTime.get();
            if (t == null) {
                failureStartTime.set(clock.instant());
            } else if (Duration.between(t, clock.instant()).compareTo(this.shutdownWaitTime) > 0) {
                LOGGER.error("core attestation has been in failed state for too long. shutting down operator");
                this.shutdownService.Shutdown(1);
            }
        }
    }
}
