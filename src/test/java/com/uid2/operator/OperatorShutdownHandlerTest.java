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
        this.operatorShutdownHandler = new OperatorShutdownHandler(Duration.ofHours(12), Duration.ofHours(12), clock, shutdownService);
    }

    @AfterEach
    void afterEach() throws Exception {
        mocks.close();
    }

    @Test
    void shutdownOnAttest401(VertxTestContext testContext) {
        ListAppender<ILoggingEvent> logWatcher = new ListAppender<>();
        logWatcher.start();
        ((Logger) LoggerFactory.getLogger(OperatorShutdownHandler.class)).addAppender(logWatcher);

        // Revoke auth
        try {
            this.operatorShutdownHandler.handleAttestResponse(Pair.of(401, "Unauthorized"));
        } catch (RuntimeException e) {
            verify(shutdownService).Shutdown(1);
            Assertions.assertTrue(logWatcher.list.get(0).getFormattedMessage().contains("core attestation failed with 401, shutting down operator, core response: "));
            testContext.completeNow();
        }
    }

    @Test
    void shutdownOnAttestFailedTooLong(VertxTestContext testContext) {
        ListAppender<ILoggingEvent> logWatcher = new ListAppender<>();
        logWatcher.start();
        ((Logger) LoggerFactory.getLogger(OperatorShutdownHandler.class)).addAppender(logWatcher);

        this.operatorShutdownHandler.handleAttestResponse(Pair.of(500, ""));

        when(clock.instant()).thenAnswer(i -> Instant.now().plus(12, ChronoUnit.HOURS).plusSeconds(60));
        try {
            this.operatorShutdownHandler.handleAttestResponse(Pair.of(500, ""));
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

        this.operatorShutdownHandler.handleAttestResponse(Pair.of(500, ""));
        when(clock.instant()).thenAnswer(i -> Instant.now().plus(6, ChronoUnit.HOURS));
        this.operatorShutdownHandler.handleAttestResponse(Pair.of(200, ""));

        when(clock.instant()).thenAnswer(i -> Instant.now().plus(12, ChronoUnit.HOURS));
        assertDoesNotThrow(() -> {
            this.operatorShutdownHandler.handleAttestResponse(Pair.of(500, ""));
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
}
