package com.uid2.operator;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.uid2.operator.service.ShutdownService;
import com.uid2.operator.vertx.OperatorShutdownHandler;
import com.uid2.shared.attest.AttestationResponseCode;
import io.vertx.core.Vertx;
import io.vertx.junit5.VertxExtension;
import io.vertx.junit5.VertxTestContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.slf4j.LoggerFactory;
import software.amazon.awssdk.utils.Pair;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.Mockito.*;

@ExtendWith(VertxExtension.class)
public class OperatorShutdownHandlerTest {

    private AutoCloseable mocks;
    @Mock private Clock clock;
    @Mock private ShutdownService shutdownService;
    private OperatorShutdownHandler operatorShutdownHandler;



    @BeforeEach
    void beforeEach() {
        mocks = MockitoAnnotations.openMocks(this);
        when(clock.instant()).thenAnswer(i -> Instant.now());
        doThrow(new RuntimeException()).when(shutdownService).Shutdown(1);
        this.operatorShutdownHandler = new OperatorShutdownHandler(Duration.ofHours(12), Duration.ofHours(12), Duration.ofHours(12), clock, shutdownService);
    }

    @AfterEach
    void afterEach() throws Exception {
        mocks.close();
    }

    @Test
    void shutdownOnAttestFailure(VertxTestContext testContext) {
        ListAppender<ILoggingEvent> logWatcher = new ListAppender<>();
        logWatcher.start();
        ((Logger) LoggerFactory.getLogger(OperatorShutdownHandler.class)).addAppender(logWatcher);

        // Revoke auth
        try {
            this.operatorShutdownHandler.handleAttestResponse(Pair.of(AttestationResponseCode.AttestationFailure, "Unauthorized"));
        } catch (RuntimeException e) {
            verify(shutdownService).Shutdown(1);
            Assertions.assertEquals("core attestation failed with AttestationFailure, shutting down operator, core response: Unauthorized", logWatcher.list.get(0).getFormattedMessage());
            testContext.completeNow();
        }
    }

    @Test
    void shutdownOnAttestFailedTooLong(VertxTestContext testContext) {
        ListAppender<ILoggingEvent> logWatcher = new ListAppender<>();
        logWatcher.start();
        ((Logger) LoggerFactory.getLogger(OperatorShutdownHandler.class)).addAppender(logWatcher);

        this.operatorShutdownHandler.handleAttestResponse(Pair.of(AttestationResponseCode.RetryableFailure, ""));

        when(clock.instant()).thenAnswer(i -> Instant.now().plus(12, ChronoUnit.HOURS).plusSeconds(60));
        try {
            this.operatorShutdownHandler.handleAttestResponse(Pair.of(AttestationResponseCode.RetryableFailure, ""));
        } catch (RuntimeException e) {
            verify(shutdownService).Shutdown(1);
            Assertions.assertTrue(logWatcher.list.get(0).getFormattedMessage().contains("core attestation has been in failed state for too long. shutting down operator"));
            testContext.completeNow();
        }
    }

    @Test
    void attestRecoverOnSuccess(VertxTestContext testContext) {
        ListAppender<ILoggingEvent> logWatcher = new ListAppender<>();
        logWatcher.start();
        ((Logger) LoggerFactory.getLogger(OperatorShutdownHandler.class)).addAppender(logWatcher);

        this.operatorShutdownHandler.handleAttestResponse(Pair.of(AttestationResponseCode.RetryableFailure, ""));
        when(clock.instant()).thenAnswer(i -> Instant.now().plus(6, ChronoUnit.HOURS));
        this.operatorShutdownHandler.handleAttestResponse(Pair.of(AttestationResponseCode.Success, ""));

        when(clock.instant()).thenAnswer(i -> Instant.now().plus(12, ChronoUnit.HOURS));
        assertDoesNotThrow(() -> {
            this.operatorShutdownHandler.handleAttestResponse(Pair.of(AttestationResponseCode.RetryableFailure, ""));
        });
        verify(shutdownService, never()).Shutdown(anyInt());
        testContext.completeNow();
    }

    @Test
    void shutdownOnSaltsExpiredTooLong(VertxTestContext testContext) {
        ListAppender<ILoggingEvent> logWatcher = new ListAppender<>();
        logWatcher.start();
        ((Logger) LoggerFactory.getLogger(OperatorShutdownHandler.class)).addAppender(logWatcher);

        this.operatorShutdownHandler.handleSaltRetrievalResponse(true);
        Assertions.assertTrue(logWatcher.list.get(0).getFormattedMessage().contains("all salts are expired"));

        when(clock.instant()).thenAnswer(i -> Instant.now().plus(12, ChronoUnit.HOURS).plusSeconds(60));
        Assertions.assertThrows(RuntimeException.class, () -> {
            this.operatorShutdownHandler.handleSaltRetrievalResponse(true);
        });
        Assertions.assertAll("Expired Salts Log Messages",
                () -> verify(shutdownService).Shutdown(1),
                () -> Assertions.assertTrue(logWatcher.list.get(1).getFormattedMessage().contains("all salts are expired")),
                () -> Assertions.assertTrue(logWatcher.list.get(2).getFormattedMessage().contains("salts have been in expired state for too long. shutting down operator")),
                () -> Assertions.assertEquals(3, logWatcher.list.size()));

        testContext.completeNow();
    }

    @Test
    void saltsRecoverOnSuccess(VertxTestContext testContext) {
        ListAppender<ILoggingEvent> logWatcher = new ListAppender<>();
        logWatcher.start();
        ((Logger) LoggerFactory.getLogger(OperatorShutdownHandler.class)).addAppender(logWatcher);

        this.operatorShutdownHandler.handleSaltRetrievalResponse(true);
        Assertions.assertTrue(logWatcher.list.get(0).getFormattedMessage().contains("all salts are expired"));
        when(clock.instant()).thenAnswer(i -> Instant.now().plus(6, ChronoUnit.HOURS));
        this.operatorShutdownHandler.handleSaltRetrievalResponse(true);
        Assertions.assertTrue(logWatcher.list.get(1).getFormattedMessage().contains("all salts are expired"));

        when(clock.instant()).thenAnswer(i -> Instant.now().plus(12, ChronoUnit.HOURS));
        assertDoesNotThrow(() -> {
            this.operatorShutdownHandler.handleSaltRetrievalResponse(false);
        });
        Assertions.assertEquals(2, logWatcher.list.size());
        verify(shutdownService, never()).Shutdown(anyInt());

        testContext.completeNow();
    }

    @Test
    void saltsLogErrorAtInterval(VertxTestContext testContext) {
        ListAppender<ILoggingEvent> logWatcher = new ListAppender<>();
        logWatcher.start();
        ((Logger) LoggerFactory.getLogger(OperatorShutdownHandler.class)).addAppender(logWatcher);

        this.operatorShutdownHandler.handleSaltRetrievalResponse(true);
        Assertions.assertTrue(logWatcher.list.get(0).getFormattedMessage().contains("all salts are expired"));
        when(clock.instant()).thenAnswer(i -> Instant.now().plus(9, ChronoUnit.MINUTES));
        this.operatorShutdownHandler.handleSaltRetrievalResponse(true);
        Assertions.assertEquals(1, logWatcher.list.size());
        when(clock.instant()).thenAnswer(i -> Instant.now().plus(11, ChronoUnit.MINUTES));
        this.operatorShutdownHandler.handleSaltRetrievalResponse(true);
        Assertions.assertTrue(logWatcher.list.get(1).getFormattedMessage().contains("all salts are expired"));
        Assertions.assertEquals(2, logWatcher.list.size());

        testContext.completeNow();
    }

    @Test
    void storeRefreshRecordsSuccessTimestamp(VertxTestContext testContext) {
        // Simulate successful store refresh
        this.operatorShutdownHandler.handleStoreRefresh("test_store", true);
        
        // Verify no shutdown is triggered
        verify(shutdownService, never()).Shutdown(anyInt());
        testContext.completeNow();
    }

    @Test
    void storeRefreshFailureDoesNotResetTimestamp(VertxTestContext testContext) {
        // First successful refresh
        this.operatorShutdownHandler.handleStoreRefresh("test_store", true);
        
        // Then failures - shouldn't reset the timestamp
        this.operatorShutdownHandler.handleStoreRefresh("test_store", false);
        this.operatorShutdownHandler.handleStoreRefresh("test_store", false);
        
        // Verify no shutdown is triggered yet
        verify(shutdownService, never()).Shutdown(anyInt());
        testContext.completeNow();
    }

    @Test
    void storeRefreshStaleShutdown(VertxTestContext testContext) {
        ListAppender<ILoggingEvent> logWatcher = new ListAppender<>();
        logWatcher.start();
        ((Logger) LoggerFactory.getLogger(OperatorShutdownHandler.class)).addAppender(logWatcher);

        // Initial successful refresh
        this.operatorShutdownHandler.handleStoreRefresh("test_store", true);
        
        // Move time forward by 12 hours + 1 second
        when(clock.instant()).thenAnswer(i -> Instant.now().plus(12, ChronoUnit.HOURS).plusSeconds(1));
        
        // Check staleness - should trigger shutdown
        try {
            this.operatorShutdownHandler.checkStoreRefreshStaleness();
        } catch (RuntimeException e) {
            verify(shutdownService).Shutdown(1);
            Assertions.assertTrue(logWatcher.list.stream().anyMatch(log -> 
                log.getFormattedMessage().contains("has not refreshed successfully") && 
                log.getFormattedMessage().contains("test_store")));
            testContext.completeNow();
        }
    }

    @Test
    void storeRefreshRecoverBeforeStale(VertxTestContext testContext) {
        // Initial successful refresh
        this.operatorShutdownHandler.handleStoreRefresh("test_store", true);
        
        // Move time forward by 11 hours
        when(clock.instant()).thenAnswer(i -> Instant.now().plus(11, ChronoUnit.HOURS));
        
        // Another successful refresh before timeout
        this.operatorShutdownHandler.handleStoreRefresh("test_store", true);
        
        // Move time forward another 12 hours from original time (but only 1 hour from last refresh)
        when(clock.instant()).thenAnswer(i -> Instant.now().plus(12, ChronoUnit.HOURS));
        
        // Check staleness - should NOT trigger shutdown
        assertDoesNotThrow(() -> {
            this.operatorShutdownHandler.checkStoreRefreshStaleness();
        });
        verify(shutdownService, never()).Shutdown(anyInt());
        testContext.completeNow();
    }

    @Test
    void multipleStoresOneStaleTriggers(VertxTestContext testContext) {
        ListAppender<ILoggingEvent> logWatcher = new ListAppender<>();
        logWatcher.start();
        ((Logger) LoggerFactory.getLogger(OperatorShutdownHandler.class)).addAppender(logWatcher);

        // Multiple stores succeed
        this.operatorShutdownHandler.handleStoreRefresh("store1", true);
        this.operatorShutdownHandler.handleStoreRefresh("store2", true);
        this.operatorShutdownHandler.handleStoreRefresh("store3", true);
        
        // Move time forward
        when(clock.instant()).thenAnswer(i -> Instant.now().plus(6, ChronoUnit.HOURS));
        
        // Store1 and Store2 refresh successfully, but Store3 doesn't
        this.operatorShutdownHandler.handleStoreRefresh("store1", true);
        this.operatorShutdownHandler.handleStoreRefresh("store2", true);
        
        // Move time forward 12 hours from start (store3 hasn't refreshed for 12 hours)
        when(clock.instant()).thenAnswer(i -> Instant.now().plus(12, ChronoUnit.HOURS).plusSeconds(1));
        
        // Check staleness - should trigger shutdown for store3
        try {
            this.operatorShutdownHandler.checkStoreRefreshStaleness();
        } catch (RuntimeException e) {
            verify(shutdownService).Shutdown(1);
            Assertions.assertTrue(logWatcher.list.stream().anyMatch(log -> 
                log.getFormattedMessage().contains("store3") && 
                log.getFormattedMessage().contains("has not refreshed successfully")));
            testContext.completeNow();
        }
    }

    @Test
    void noShutdownWhenStoreNeverInitialized(VertxTestContext testContext) {
        // Don't register any successful refresh for a store
        // Just check staleness immediately
        assertDoesNotThrow(() -> {
            this.operatorShutdownHandler.checkStoreRefreshStaleness();
        });
        verify(shutdownService, never()).Shutdown(anyInt());
        testContext.completeNow();
    }

    @Test
    void periodicCheckStartsSuccessfully(Vertx vertx, VertxTestContext testContext) {
        // Start the periodic check
        assertDoesNotThrow(() -> {
            this.operatorShutdownHandler.startPeriodicStaleCheck(vertx);
        });
        
        // Verify it doesn't crash and doesn't trigger shutdown immediately
        verify(shutdownService, never()).Shutdown(anyInt());
        testContext.completeNow();
    }

    @Test
    void periodicCheckOnlyStartsOnce(Vertx vertx, VertxTestContext testContext) {
        ListAppender<ILoggingEvent> logWatcher = new ListAppender<>();
        logWatcher.start();
        ((Logger) LoggerFactory.getLogger(OperatorShutdownHandler.class)).addAppender(logWatcher);

        // Start the periodic check twice
        this.operatorShutdownHandler.startPeriodicStaleCheck(vertx);
        this.operatorShutdownHandler.startPeriodicStaleCheck(vertx);
        
        // Should log a warning
        Assertions.assertTrue(logWatcher.list.stream().anyMatch(log -> 
            log.getFormattedMessage().contains("already started")));
        testContext.completeNow();
    }
}
