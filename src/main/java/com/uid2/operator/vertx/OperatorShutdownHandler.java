package com.uid2.operator.vertx;

import com.uid2.operator.service.ShutdownService;
import com.uid2.shared.attest.AttestationResponseCode;
import io.vertx.core.Vertx;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.utils.Pair;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

public class OperatorShutdownHandler {
    private static final Logger LOGGER = LoggerFactory.getLogger(OperatorShutdownHandler.class);
    private static final int SALT_FAILURE_LOG_INTERVAL_MINUTES = 10;
    private static final int STORE_REFRESH_STALENESS_CHECK_INTERVAL_MINUTES = 60;
    private final Duration attestShutdownWaitTime;
    private final Duration saltShutdownWaitTime;
    private final Duration storeRefreshStaleTimeout;
    private final AtomicReference<Instant> attestFailureStartTime = new AtomicReference<>(null);
    private final AtomicReference<Instant> saltFailureStartTime = new AtomicReference<>(null);
    private final AtomicReference<Instant> lastSaltFailureLogTime = new AtomicReference<>(null);
    private final Map<String, AtomicReference<Instant>> lastSuccessfulRefreshTimes = new ConcurrentHashMap<>();
    private final Clock clock;
    private final ShutdownService shutdownService;
    private long periodicCheckTimerId = -1;

    public OperatorShutdownHandler(Duration attestShutdownWaitTime, Duration saltShutdownWaitTime,
            Duration storeRefreshStaleTimeout, Clock clock, ShutdownService shutdownService) {
        this.attestShutdownWaitTime = attestShutdownWaitTime;
        this.saltShutdownWaitTime = saltShutdownWaitTime;
        this.storeRefreshStaleTimeout = storeRefreshStaleTimeout;
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

    public void handleStoreRefresh(String storeName, Boolean success) {
        if (success) {
            lastSuccessfulRefreshTimes.computeIfAbsent(storeName, k -> new AtomicReference<>())
                    .set(clock.instant());
            LOGGER.trace("Store {} refresh successful at {}", storeName, clock.instant());
        } else {
            LOGGER.debug("Store {} refresh failed, timestamp not updated", storeName);
        }
    }

    public void checkStoreRefreshStaleness() {
        Instant now = clock.instant();
        for (Map.Entry<String, AtomicReference<Instant>> entry : lastSuccessfulRefreshTimes.entrySet()) {
            String storeName = entry.getKey();
            Instant lastSuccess = entry.getValue().get();

            if (lastSuccess == null) {
                // Store hasn't had a successful refresh yet - might be during startup
                // Don't trigger shutdown for stores that haven't initialized
                continue;
            }

            Duration timeSinceLastRefresh = Duration.between(lastSuccess, now);
            if (timeSinceLastRefresh.compareTo(storeRefreshStaleTimeout) > 0) {
                LOGGER.error("Store '{}' has not refreshed successfully for {} hours ({}). Shutting down operator",
                        storeName, timeSinceLastRefresh.toHours(), timeSinceLastRefresh);
                shutdownService.Shutdown(1);
                return; // Exit after triggering shutdown for first stale store
            }
        }
    }

    public void startPeriodicStaleCheck(Vertx vertx) {
        if (periodicCheckTimerId != -1) {
            LOGGER.warn("Periodic store staleness check already started");
            return;
        }

        long intervalMs = STORE_REFRESH_STALENESS_CHECK_INTERVAL_MINUTES * 60 * 1000L;
        periodicCheckTimerId = vertx.setPeriodic(intervalMs, id -> {
            LOGGER.debug("Running periodic store staleness check");
            checkStoreRefreshStaleness();
        });
        LOGGER.info("Started periodic store staleness check (interval: {} minutes, timeout: {} hours)",
                STORE_REFRESH_STALENESS_CHECK_INTERVAL_MINUTES,
                storeRefreshStaleTimeout.toHours());
    }
}
