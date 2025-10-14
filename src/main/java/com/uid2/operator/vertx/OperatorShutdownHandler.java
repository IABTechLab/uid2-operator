package com.uid2.operator.vertx;

import com.uid2.operator.service.ShutdownService;
import com.uid2.shared.attest.AttestationResponseCode;
import lombok.extern.java.Log;
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
    private static final int SALT_FAILURE_LOG_INTERVAL_MINUTES = 10;
    private final Duration attestShutdownWaitTime;
    private final Duration saltShutdownWaitTime;
    private final Duration keysetKeyShutdownWaitTime;
    private final AtomicReference<Instant> attestFailureStartTime = new AtomicReference<>(null);
    private final AtomicReference<Instant> saltFailureStartTime = new AtomicReference<>(null);
    private final AtomicReference<Instant> keysetKeyFailureStartTime = new AtomicReference<>(null);
    private final AtomicReference<Instant> lastSaltFailureLogTime = new AtomicReference<>(null);
    private final Clock clock;
    private final ShutdownService shutdownService;

    public OperatorShutdownHandler(Duration attestShutdownWaitTime, Duration saltShutdownWaitTime,
            Duration keysetKeyShutdownWaitTime, Clock clock, ShutdownService shutdownService) {
        this.attestShutdownWaitTime = attestShutdownWaitTime;
        this.saltShutdownWaitTime = saltShutdownWaitTime;
        this.keysetKeyShutdownWaitTime = keysetKeyShutdownWaitTime;
        this.clock = clock;
        this.shutdownService = shutdownService;
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
                this.shutdownService.Shutdown(1);
            }
        }
    }

    public void logSaltFailureAtInterval() {
        Instant t = lastSaltFailureLogTime.get();
        if(t == null || clock.instant().isAfter(t.plus(SALT_FAILURE_LOG_INTERVAL_MINUTES, ChronoUnit.MINUTES))) {
            LOGGER.error("all salts are expired");
            lastSaltFailureLogTime.set(Instant.now());
        }
    }

    public void handleKeysetKeyRefreshResponse(Boolean success) {
        if (success) {
            keysetKeyFailureStartTime.set(null);
            LOGGER.debug("keyset keys sync successful"); 
        } else {
            Instant t = keysetKeyFailureStartTime.get();
            if (t == null) {
                keysetKeyFailureStartTime.set(clock.instant());
                LOGGER.warn("keyset keys sync started failing. shutdown timer started");
            } else {
                Duration elapsed = Duration.between(t, clock.instant());
                LOGGER.debug("keyset keys sync still failing - elapsed time: {}d {}h {}m",
                        elapsed.toDays(),
                        elapsed.toHoursPart(),
                        elapsed.toMinutesPart());
                if (elapsed.compareTo(this.keysetKeyShutdownWaitTime) > 0) {
                    LOGGER.error("keyset keys have been failing to sync for too long. shutting down operator");
                    this.shutdownService.Shutdown(1);
                }
            }
        }
    }

    public void handleAttestResponse(Pair<AttestationResponseCode, String> response) {
        if (response.left() == AttestationResponseCode.AttestationFailure) {
            LOGGER.error("core attestation failed with AttestationFailure, shutting down operator, core response: {}", response.right());
            this.shutdownService.Shutdown(1);
        }
        if (response.left() == AttestationResponseCode.Success) {
            attestFailureStartTime.set(null);
        } else {
            Instant t = attestFailureStartTime.get();
            if (t == null) {
                attestFailureStartTime.set(clock.instant());
            } else if (Duration.between(t, clock.instant()).compareTo(this.attestShutdownWaitTime) > 0) {
                LOGGER.error("core attestation has been in failed state for too long. shutting down operator");
                this.shutdownService.Shutdown(1);
            }
        }
    }
}
