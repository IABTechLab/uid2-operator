package com.uid2.operator;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.uid2.operator.service.ShutdownService;
import com.uid2.operator.vertx.OperatorShutdownHandler;
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

import java.security.Permission;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.Mockito.*;

@ExtendWith(VertxExtension.class)
public class OperatorShutdownHandlerTest {

    private AutoCloseable mocks;
    @Mock
    private Clock clock;

    @Mock
    private ShutdownService shutdownService;

    private OperatorShutdownHandler operatorShutdownHandler;

    @BeforeEach
    void beforeEach() {
        mocks = MockitoAnnotations.openMocks(this);
        when(clock.instant()).thenAnswer(i -> Instant.now());
        doThrow(new RuntimeException()).when(shutdownService).Shutdown(1);
        this.operatorShutdownHandler = new OperatorShutdownHandler(Duration.ofHours(12), clock, shutdownService);
    }

    @AfterEach
    void afterEach() throws Exception {
        mocks.close();
    }


    // These tests have been removed as Java 21 does not support the getSecurityManager. Another approach will need to be found.
    @Test
    void shutdownOn401(Vertx vertx, VertxTestContext testContext) {
        try {
            ListAppender<ILoggingEvent> logWatcher = new ListAppender<>();
            logWatcher.start();
            ((Logger) LoggerFactory.getLogger(OperatorShutdownHandler.class)).addAppender(logWatcher);

            // Revoke auth
            try {
                this.operatorShutdownHandler.handleResponse(Pair.of(401, "Unauthorized"));
            } catch (RuntimeException e) {
                verify(shutdownService).Shutdown(1);
                Assertions.assertTrue(logWatcher.list.get(0).getFormattedMessage().contains("core attestation failed with 401, shutting down operator, core response: "));
                testContext.completeNow();
            }
        } finally {
        }
    }

    @Test
    void shutdownOnFailedTooLong(Vertx vertx, VertxTestContext testContext) {

        ListAppender<ILoggingEvent> logWatcher = new ListAppender<>();
        logWatcher.start();
        ((Logger) LoggerFactory.getLogger(OperatorShutdownHandler.class)).addAppender(logWatcher);

        this.operatorShutdownHandler.handleResponse(Pair.of(500, ""));

        when(clock.instant()).thenAnswer(i -> Instant.now().plus(12, ChronoUnit.HOURS).plusSeconds(60));
        try {
            this.operatorShutdownHandler.handleResponse(Pair.of(500, ""));
        } catch (RuntimeException e) {
            verify(shutdownService).Shutdown(1);
            Assertions.assertTrue(logWatcher.list.get(0).getFormattedMessage().contains("core attestation has been in failed state for too long. shutting down operator"));
            testContext.completeNow();
        }
    }

    @Test
    void attestRecoverOnSuccess(Vertx vertx, VertxTestContext testContext) {
        ListAppender<ILoggingEvent> logWatcher = new ListAppender<>();
        logWatcher.start();
        ((Logger) LoggerFactory.getLogger(OperatorShutdownHandler.class)).addAppender(logWatcher);

        this.operatorShutdownHandler.handleResponse(Pair.of(500, ""));
        when(clock.instant()).thenAnswer(i -> Instant.now().plus(6, ChronoUnit.HOURS));
        this.operatorShutdownHandler.handleResponse(Pair.of(200, ""));

        when(clock.instant()).thenAnswer(i -> Instant.now().plus(12, ChronoUnit.HOURS));
        assertDoesNotThrow(() -> {
            this.operatorShutdownHandler.handleResponse(Pair.of(500, ""));
        });
        testContext.completeNow();
    }
}
