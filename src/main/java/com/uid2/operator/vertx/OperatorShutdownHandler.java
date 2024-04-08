package com.uid2.operator.vertx;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.utils.Pair;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.concurrent.atomic.AtomicReference;

public class OperatorShutdownHandler {
    private static final Logger LOGGER = LoggerFactory.getLogger(OperatorShutdownHandler.class);
    private final Duration attestShutdownWaitTime;
    private final Duration saltShutdownWaitTime;
    private final AtomicReference<Instant> attestFailureStartTime = new AtomicReference<>(null);
    private final AtomicReference<Instant> saltFailureStartTime = new AtomicReference<>(null);
    private final AtomicReference<Instant> lastSaltFailureLogTime = new AtomicReference<>(null);
    private final Clock clock;

    public OperatorShutdownHandler(Duration attestShutdownWaitTime, Duration saltShutdownWaitTime, Clock clock) {
        this.attestShutdownWaitTime = attestShutdownWaitTime;
        this.saltShutdownWaitTime = saltShutdownWaitTime;
        this.clock = clock;
    }

    public void handleSaltRetrievalResponse(Boolean expired) {
        if(!expired) {
            saltFailureStartTime.set(null);
        } else {
            logSaltFailureAtInterval();
            Instant t = saltFailureStartTime.get();
            if (t == null) {
                saltFailureStartTime.set(clock.instant());
            } else if(Duration.between(t, clock.instant()).compareTo(this.saltShutdownWaitTime) > 0) {
                LOGGER.error("salts have been in expired state for too long. shutting down operator");
                System.exit(1);
            }
        }
    }

    public void logSaltFailureAtInterval() {
        Instant t = lastSaltFailureLogTime.get();
        if(t == null || clock.instant().isAfter(t.plus(10, ChronoUnit.MINUTES))) {
            LOGGER.error("all salts are expired");
            lastSaltFailureLogTime.set(Instant.now());
        }
    }

    public void handleAttestResponse(Pair<Integer, String> response) {
        if (response.left() == 401) {
            LOGGER.error("core attestation failed with 401, shutting down operator, core response: " + response.right());
            System.exit(1);
        }
        if (response.left() == 200) {
            attestFailureStartTime.set(null);
        } else {
            Instant t = attestFailureStartTime.get();
            if (t == null) {
                attestFailureStartTime.set(clock.instant());
            } else if (Duration.between(t, clock.instant()).compareTo(this.attestShutdownWaitTime) > 0) {
                LOGGER.error("core attestation has been in failed state for too long. shutting down operator");
                System.exit(1);
            }
        }
    }
}
