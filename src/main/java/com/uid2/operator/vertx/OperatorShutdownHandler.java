package com.uid2.operator.vertx;

import com.uid2.operator.service.ShutdownService;
import com.uid2.shared.attest.AttestationResponseCode;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.client.HttpRequest;
import io.vertx.ext.web.client.HttpResponse;
import io.vertx.ext.web.client.WebClient;
import io.vertx.ext.web.codec.BodyCodec;
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
    private static volatile OperatorShutdownHandler instance = null;
    private static final Logger LOGGER = LoggerFactory.getLogger(OperatorShutdownHandler.class);
    private static final int SALT_FAILURE_LOG_INTERVAL_MINUTES = 10;
    private static final int STORE_REFRESH_STALENESS_CHECK_INTERVAL_MINUTES = 60;
    private final Duration attestShutdownWaitTime;
    private final Duration saltShutdownWaitTime;
    private final Duration storeRefreshStaleTimeout;
    private final Duration timeDriftThreshold;
    private final Duration timeDriftCriticalThreshold;
    private final AtomicReference<Instant> attestFailureStartTime = new AtomicReference<>(null);
    private final AtomicReference<Instant> saltFailureStartTime = new AtomicReference<>(null);
    private final AtomicReference<Instant> lastSaltFailureLogTime = new AtomicReference<>(null);
    private final Map<String, AtomicReference<Instant>> lastSuccessfulRefreshTimes = new ConcurrentHashMap<>();
    private final Clock clock;
    private final ShutdownService shutdownService;
    private final Vertx vertx;
    private final boolean timeDriftShutdownEnabled;
    private boolean isStalenessCheckScheduled = false;
    private boolean isTimeDriftCheckScheduled = false;
    private volatile Instant testModeReferenceTime = null; // For testing: allows injecting fake reference time
    // Time correction: tracks the offset to apply to correct for time drift
    private final AtomicReference<Duration> timeOffset = new AtomicReference<>(Duration.ZERO);
    private final AtomicReference<Instant> lastTimeDriftCheckTime = new AtomicReference<>(null);

    public OperatorShutdownHandler(Duration attestShutdownWaitTime, Duration saltShutdownWaitTime,
            Duration storeRefreshStaleTimeout, Clock clock, ShutdownService shutdownService) {
        this(attestShutdownWaitTime, saltShutdownWaitTime, storeRefreshStaleTimeout, clock, shutdownService, null, false, Duration.ofSeconds(30), Duration.ofSeconds(300));
    }

    public OperatorShutdownHandler(Duration attestShutdownWaitTime, Duration saltShutdownWaitTime,
            Duration storeRefreshStaleTimeout, Clock clock, ShutdownService shutdownService, Vertx vertx,
            boolean timeDriftShutdownEnabled, Duration timeDriftThreshold) {
        this(attestShutdownWaitTime, saltShutdownWaitTime, storeRefreshStaleTimeout, clock, shutdownService, vertx, timeDriftShutdownEnabled, timeDriftThreshold, Duration.ofSeconds(300));
    }

    public OperatorShutdownHandler(Duration attestShutdownWaitTime, Duration saltShutdownWaitTime,
            Duration storeRefreshStaleTimeout, Clock clock, ShutdownService shutdownService, Vertx vertx,
            boolean timeDriftShutdownEnabled, Duration timeDriftThreshold, Duration timeDriftCriticalThreshold) {
        this.attestShutdownWaitTime = attestShutdownWaitTime;
        this.saltShutdownWaitTime = saltShutdownWaitTime;
        this.storeRefreshStaleTimeout = storeRefreshStaleTimeout;
        this.clock = clock;
        this.shutdownService = shutdownService;
        this.vertx = vertx;
        this.timeDriftShutdownEnabled = timeDriftShutdownEnabled;
        this.timeDriftThreshold = timeDriftThreshold;
        this.timeDriftCriticalThreshold = timeDriftCriticalThreshold;
        instance = this; // Set static instance for test endpoint access
    }

    /**
     * Get the singleton instance (for test endpoint access)
     */
    public static OperatorShutdownHandler getInstance() {
        return instance;
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

    public void handleStoreRefresh(String storeName) {
        lastSuccessfulRefreshTimes.computeIfAbsent(storeName, k -> new AtomicReference<>())
                .set(clock.instant());
    }

    public void checkStoreRefreshStaleness() {
        Instant now = clock.instant();
        for (Map.Entry<String, AtomicReference<Instant>> entry : lastSuccessfulRefreshTimes.entrySet()) {
            String storeName = entry.getKey();
            Instant lastSuccess = entry.getValue().get();

            if (lastSuccess == null) {
                // Store hasn't had a successful refresh yet
                // This should rarely happen since startup success also records timestamp, but keep as defensive guard for edge cases
                LOGGER.warn("Store '{}' has no recorded successful refresh - skipping staleness check", storeName);
                continue;
            }

            Duration timeSinceLastRefresh = Duration.between(lastSuccess, now);
            LOGGER.debug("Store '{}' last successful refresh {} ago", storeName, timeSinceLastRefresh);
            if (timeSinceLastRefresh.compareTo(storeRefreshStaleTimeout) > 0) {
                LOGGER.error("Store '{}' has not refreshed successfully for {} hours ({}). Shutting down operator",
                        storeName, timeSinceLastRefresh.toHours(), timeSinceLastRefresh);
                this.shutdownService.Shutdown(1);
                return; // Exit after triggering shutdown for first stale store
            }
        }
    }

    public void startPeriodicStaleCheck(Vertx vertx) {
        if (isStalenessCheckScheduled) {
            LOGGER.warn("Periodic store staleness check already started");
            return;
        }

        long intervalMs = STORE_REFRESH_STALENESS_CHECK_INTERVAL_MINUTES * 60 * 1000L;
        vertx.setPeriodic(intervalMs, id -> {
            LOGGER.debug("Running periodic store staleness check");
            checkStoreRefreshStaleness();
        });
        isStalenessCheckScheduled = true;
        LOGGER.info("Started periodic store staleness check (interval: {} minutes, timeout: {} hours)",
                STORE_REFRESH_STALENESS_CHECK_INTERVAL_MINUTES,
                storeRefreshStaleTimeout.toHours());
    }

    public void startPeriodicTimeDriftCheck(Vertx vertx, int checkIntervalMinutes) {
        if (!timeDriftShutdownEnabled) {
            LOGGER.info("Time drift shutdown is disabled, skipping periodic time drift check");
            return;
        }

        if (isTimeDriftCheckScheduled) {
            LOGGER.warn("Periodic time drift check already started");
            return;
        }

        long intervalMs = checkIntervalMinutes * 60 * 1000L;
        vertx.setPeriodic(intervalMs, id -> {
            LOGGER.debug("Running periodic time drift check");
            checkTimeDrift();
        });
        isTimeDriftCheckScheduled = true;
        LOGGER.info("Started periodic time drift check (interval: {} minutes, threshold: {} seconds)",
                checkIntervalMinutes, timeDriftThreshold.getSeconds());
    }

    /**
     * Manually trigger time drift check (for testing/debugging)
     */
    public void triggerTimeDriftCheck() {
        checkTimeDrift();
    }

    /**
     * Set test mode reference time (for testing only)
     * This allows simulating time drift by injecting a fake reference time
     */
    public void setTestModeReferenceTime(Instant testReferenceTime) {
        this.testModeReferenceTime = testReferenceTime;
        LOGGER.warn("TEST MODE: Time drift check will use injected reference time: {}", testReferenceTime);
    }

    /**
     * Clear test mode (use real time service)
     */
    public void clearTestMode() {
        this.testModeReferenceTime = null;
        LOGGER.info("Test mode cleared, using real time service");
    }

    /**
     * Get the current time offset being applied for time correction
     * @return Duration offset (positive means we add time, negative means we subtract time)
     */
    public Duration getTimeOffset() {
        return timeOffset.get();
    }

    /**
     * Get corrected time (current time + offset)
     * This should be used for time-sensitive operations that need accurate time
     * @return Corrected Instant
     */
    public Instant getCorrectedTime() {
        Duration offset = timeOffset.get();
        if (offset.isZero()) {
            return clock.instant();
        }
        return clock.instant().plus(offset);
    }

    /**
     * Get time drift status information
     * @return JsonObject with current drift status
     */
    public JsonObject getTimeDriftStatus() {
        JsonObject status = new JsonObject();
        Duration offset = timeOffset.get();
        status.put("offset_seconds", offset.getSeconds());
        status.put("offset_nanos", offset.getNano());
        status.put("has_offset", !offset.isZero());
        status.put("current_time", clock.instant().toString());
        status.put("corrected_time", getCorrectedTime().toString());
        
        Instant lastCheck = lastTimeDriftCheckTime.get();
        if (lastCheck != null) {
            status.put("last_check_time", lastCheck.toString());
            Duration timeSinceLastCheck = Duration.between(lastCheck, clock.instant());
            status.put("seconds_since_last_check", timeSinceLastCheck.getSeconds());
        }
        
        return status;
    }

    private void checkTimeDrift() {
        if (vertx == null) {
            LOGGER.warn("Vertx not available for time drift check");
            return;
        }

        // Test mode: use injected reference time
        if (testModeReferenceTime != null) {
            Instant referenceTime = testModeReferenceTime;
            Instant enclaveTime = clock.instant();
            Duration drift = Duration.between(referenceTime, enclaveTime);
            Duration driftAbs = drift.abs();
            
            LOGGER.warn("TEST MODE: Time drift check using injected reference time");
            LOGGER.warn("Time drift check: reference={}, enclave={}, drift={}s",
                    referenceTime, enclaveTime, drift.getSeconds());
            
            handleTimeDrift(drift, driftAbs);
            return;
        }

        // Production mode: use worldtimeapi.org as a reliable time reference
        WebClient webClient = WebClient.create(vertx);
        HttpRequest<String> request = webClient.get(443, "worldtimeapi.org", "/api/timezone/Etc/UTC")
                .ssl(true)
                .as(BodyCodec.string());
        
        request.send(ar -> {
            if (ar.failed()) {
                LOGGER.warn("Time drift check request failed: {}", ar.cause().getMessage());
                return;
            }
            
            HttpResponse<String> response = ar.result();
            if (response.statusCode() == 200) {
                try {
                    JsonObject timeResponse = new JsonObject(response.body());
                    String datetimeStr = timeResponse.getString("datetime");
                    
                    // Parse ISO 8601 format: "2024-01-01T12:00:00.123456+00:00"
                    Instant referenceTime = Instant.parse(datetimeStr);
                    Instant enclaveTime = clock.instant();
                    
                    // Calculate drift: negative means enclave is behind, positive means ahead
                    // Duration.between(referenceTime, enclaveTime) = enclaveTime - referenceTime
                    Duration drift = Duration.between(referenceTime, enclaveTime);
                    Duration driftAbs = drift.abs();
                    
                    LOGGER.debug("Time drift check: reference={}, enclave={}, drift={}s",
                            referenceTime, enclaveTime, drift.getSeconds());
                    
                    handleTimeDrift(drift, driftAbs);
                    lastTimeDriftCheckTime.set(clock.instant());
                } catch (Exception e) {
                    LOGGER.warn("Failed to parse time drift response: {}", e.getMessage());
                }
            } else {
                LOGGER.warn("Time drift check failed: HTTP status {}", response.statusCode());
            }
        });
    }

    /**
     * Handle detected time drift by applying correction or shutting down if critical
     * @param drift Duration drift (negative = enclave behind, positive = enclave ahead)
     * @param driftAbs Absolute value of drift
     */
    private void handleTimeDrift(Duration drift, Duration driftAbs) {
        // If drift exceeds critical threshold, shutdown (instance replacement needed)
        if (driftAbs.compareTo(timeDriftCriticalThreshold) > 0) {
            LOGGER.error("CRITICAL time drift detected: {} seconds (critical threshold: {} seconds). " +
                    "Drift is too large to correct. Shutting down operator to trigger instance replacement.",
                    driftAbs.getSeconds(), timeDriftCriticalThreshold.getSeconds());
            this.shutdownService.Shutdown(1);
            return;
        }

        // If drift exceeds normal threshold, apply time correction
        if (driftAbs.compareTo(timeDriftThreshold) > 0) {
            // Update the time offset to correct for drift
            // If enclave is behind (negative drift), we add a positive offset to correct it
            // If enclave is ahead (positive drift), we add a negative offset to correct it
            // So we negate the drift to get the correction offset
            Duration newOffset = drift.negated();
            
            Duration oldOffset = timeOffset.getAndSet(newOffset);
            
            if (!oldOffset.equals(newOffset)) {
                LOGGER.warn("Time drift detected: {} seconds (threshold: {} seconds). " +
                        "Applying time correction offset: {} seconds. " +
                        "Previous offset: {} seconds. " +
                        "This will be applied to time-sensitive operations.",
                        driftAbs.getSeconds(), timeDriftThreshold.getSeconds(),
                        newOffset.getSeconds(), oldOffset.getSeconds());
            } else {
                LOGGER.debug("Time drift correction already applied: offset={}s, drift={}s",
                        newOffset.getSeconds(), driftAbs.getSeconds());
            }
        } else {
            // Drift is within acceptable range
            // If we had a previous offset, check if we should clear it (drift has corrected itself)
            Duration currentOffset = timeOffset.get();
            if (!currentOffset.isZero()) {
                // If current drift is small and offset exists, we might want to gradually reduce it
                // For now, keep the offset but log that drift is now acceptable
                LOGGER.debug("Time drift within acceptable range: drift={}s (threshold: {}s), " +
                        "but offset correction still active: {}s",
                        driftAbs.getSeconds(), timeDriftThreshold.getSeconds(), currentOffset.getSeconds());
            } else {
                LOGGER.debug("Time drift check passed: drift={}s (threshold: {}s)",
                        driftAbs.getSeconds(), timeDriftThreshold.getSeconds());
            }
        }
    }
}
