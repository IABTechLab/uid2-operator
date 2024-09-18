package com.uid2.operator;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.uid2.operator.model.StatsCollectorMessageItem;
import com.uid2.operator.monitoring.StatsCollectorVerticle;
import com.uid2.operator.vertx.Endpoints;
import io.vertx.core.Vertx;
import io.vertx.junit5.VertxExtension;
import io.vertx.junit5.VertxTestContext;
import static org.assertj.core.api.Assertions.*;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

@ExtendWith(VertxExtension.class)
public class StatsCollectorVerticleTest {
    private static final int MAX_INVALID_PATHS = 5;
    private static final int MAX_CLIENT_VERSION_BUCKETS = 8;
    private static final int JSON_INTERVAL = 200;
    private static final int LOG_WAIT_INTERVAL = 50;
    private static final String CLIENT_VERSION = "uid2-sdk-3.0.0";
    private final ObjectMapper mapper = new ObjectMapper();
    private ListAppender<ILoggingEvent> logWatcher;
    private Vertx vertx;

    @BeforeEach
    void deployVerticle(Vertx vertx, VertxTestContext testContext) {
        this.vertx = vertx;
        var verticle = new StatsCollectorVerticle(JSON_INTERVAL, MAX_INVALID_PATHS, MAX_CLIENT_VERSION_BUCKETS);
        vertx.deployVerticle(verticle, testContext.succeeding(id -> testContext.completeNow()));

        logWatcher = new ListAppender<>();
        logWatcher.start();
        ((Logger) LoggerFactory.getLogger(StatsCollectorVerticle.class)).addAppender(logWatcher);
    }

    @AfterEach
    void cleanupLogger() {
        logWatcher.stop();
        ((Logger) LoggerFactory.getLogger(StatsCollectorVerticle.class)).detachAppender(logWatcher);
    }

    @Test
    void verticleDeployed(Vertx vertx, VertxTestContext testContext) {
       testContext.completeNow();
    }

    private List<String> getMessages() {
        return logWatcher.list.stream().map(ILoggingEvent::getFormattedMessage).collect(Collectors.toList());
    }

    private void sendStatMessage(StatsCollectorMessageItem messageItem) throws JsonProcessingException {
        vertx.eventBus().send(Const.Config.StatsCollectorEventBus, mapper.writeValueAsString(messageItem));
    }

    private void triggerSerializeAndWait(VertxTestContext testContext) throws JsonProcessingException, InterruptedException {
        StatsCollectorMessageItem triggerSerialize = new StatsCollectorMessageItem("/triggerSerialize", "https://test.com", "test", null, null);
        sendStatMessage(triggerSerialize);
        testContext.awaitCompletion(LOG_WAIT_INTERVAL, TimeUnit.MILLISECONDS);
    }

    @Test
    void testJSONSerializeWithV0AndV1Paths(Vertx vertx, VertxTestContext testContext) throws InterruptedException, JsonProcessingException {
        StatsCollectorMessageItem messageItem = new StatsCollectorMessageItem("/test", "https://test.com", "test", 1, CLIENT_VERSION);
        sendStatMessage(messageItem);
        sendStatMessage(messageItem);
        sendStatMessage(messageItem);

        messageItem = new StatsCollectorMessageItem("/v1/test", "https://test.com", "test", 1, CLIENT_VERSION);
        sendStatMessage(messageItem);
        sendStatMessage(messageItem);
        waitForLogInterval(testContext);

        triggerSerializeAndWait(testContext);

        var expectedList = List.of("{\"endpoint\":\"test\",\"siteId\":1,\"apiVersion\":\"v1\",\"domainList\":[{\"domain\":\"test.com\",\"count\":2,\"apiContact\":\"test\"}]}",
                            "{\"endpoint\":\"test\",\"siteId\":1,\"apiVersion\":\"v0\",\"domainList\":[{\"domain\":\"test.com\",\"count\":3,\"apiContact\":\"test\"}]}");
        var messages = getMessages();
        assertThat(messages).containsAll(expectedList);

        testContext.completeNow();
    }

    private static void waitForLogInterval(VertxTestContext testContext) throws InterruptedException {
        testContext.awaitCompletion(JSON_INTERVAL*2, TimeUnit.MILLISECONDS);
    }

    @Test
    void testJSONSerializeWithV2AndUnknownPaths(Vertx vertx, VertxTestContext testContext) throws InterruptedException, JsonProcessingException {
        StatsCollectorMessageItem messageItem = new StatsCollectorMessageItem("/v2/test", "https://test.com", "test", 1, CLIENT_VERSION);
        sendStatMessage(messageItem);
        sendStatMessage(messageItem);
        sendStatMessage(messageItem);

        messageItem = new StatsCollectorMessageItem("/v2", "https://test.com", "test", 1, CLIENT_VERSION);
        sendStatMessage(messageItem);
        sendStatMessage(messageItem);
        waitForLogInterval(testContext);
        triggerSerializeAndWait(testContext);

        var expectedList = List.of("{\"endpoint\":\"test\",\"siteId\":1,\"apiVersion\":\"v2\",\"domainList\":[{\"domain\":\"test.com\",\"count\":3,\"apiContact\":\"test\"}]}",
                        "{\"endpoint\":\"v2\",\"siteId\":1,\"apiVersion\":\"unknown\",\"domainList\":[{\"domain\":\"test.com\",\"count\":2,\"apiContact\":\"test\"}]}");
        var messages = getMessages();
        assertThat(messages).containsAll(expectedList);

        testContext.completeNow();
    }

    @Test
    void allValidPathsAllowed(Vertx vertx, VertxTestContext testContext) throws InterruptedException, JsonProcessingException {
        Set<String> validEndpoints = Endpoints.pathSet();
        for(String endpoint : validEndpoints) {
            StatsCollectorMessageItem messageItem = new StatsCollectorMessageItem(endpoint, "https://test.com", "test", 1, CLIENT_VERSION);
            sendStatMessage(messageItem);
        }

        waitForLogInterval(testContext);
        triggerSerializeAndWait(testContext);

        var messages = getMessages();
        for(String endpoint: validEndpoints) {
            String withoutVersion = endpoint;
            if (endpoint.startsWith("/v1/") || endpoint.startsWith("/v2/")) {
                withoutVersion = endpoint.substring(4);
            } else if (endpoint.startsWith("/")) {
                withoutVersion = endpoint.substring(1);
            }

            String expected = "{\"endpoint\":\"" + withoutVersion + "\",\"siteId\":1,";
            assertThat(messages).anyMatch(m -> m.contains(expected));
        }

        testContext.completeNow();
    }

    @Test
    void invalidPathsLimit(Vertx vertx, VertxTestContext testContext) throws InterruptedException, JsonProcessingException {
        for(int i = 0; i < MAX_INVALID_PATHS + Endpoints.pathSet().size() + 5; i++) {
            StatsCollectorMessageItem messageItem = new StatsCollectorMessageItem("/bad" + i, "https://test.com", "test", 1, CLIENT_VERSION);
            sendStatMessage(messageItem);
        }

        waitForLogInterval(testContext);
        triggerSerializeAndWait(testContext);

        var messages = getMessages();
        // MAX_INVALID_PATHS is not the hard limit. The maximum paths that can be recorded, including valid ones, is MAX_INVALID_PATHS + validPaths.size * 2
        for(int i = 0; i < MAX_INVALID_PATHS + Endpoints.pathSet().size(); i++) {
            String expected = "{\"endpoint\":\"bad" + i + "\",\"siteId\":1,\"apiVersion\":\"v0\",\"domainList\":[{\"domain\":\"test.com\",\"count\":1,\"apiContact\":\"test\"}]}";
            assertThat(messages).contains(expected);
        }
        for(int i = MAX_INVALID_PATHS + Endpoints.pathSet().size(); i < MAX_INVALID_PATHS + 5; i++) {
            String expected = "{\"endpoint\":\"bad" + i + "\",\"siteId\":1,\"apiVersion\":\"v0\",\"domainList\":[{\"domain\":\"test.com\",\"count\":1,\"apiContact\":\"test\"}]}";
            assertThat(messages).contains(expected);
        }
        assertThat(getMessages()).contains("max invalid paths reached; a large number of invalid paths have been requested from authenticated participants");

        testContext.completeNow();
    }

    @Test
    void clientVersionStats(Vertx vertx, VertxTestContext testContext) throws InterruptedException, JsonProcessingException {
        for(int i = 0; i < 3; i++) {
            StatsCollectorMessageItem messageItem = new StatsCollectorMessageItem("/test" + i, "https://test.com", "test", 1, CLIENT_VERSION + i);
            sendStatMessage(messageItem);
        }
        for(int i = 0; i < 12; i++) {
            StatsCollectorMessageItem messageItem = new StatsCollectorMessageItem("/test" + i, "https://test.com", "test", 2, CLIENT_VERSION + i);
            for (int count = 0; count <= i; count++) {
                sendStatMessage(messageItem);
            }
        }
        sendStatMessage(new StatsCollectorMessageItem("/test", "https://test.com", "test", 2, CLIENT_VERSION + "single"));
        sendStatMessage(new StatsCollectorMessageItem("/test", "https://test.com", "test", 2, null));

        waitForLogInterval(testContext);
        triggerSerializeAndWait(testContext);

        waitForLogInterval(testContext);
        sendStatMessage(new StatsCollectorMessageItem("/test", "https://test.com", "test", 1, CLIENT_VERSION + 1));
        triggerSerializeAndWait(testContext);

        var expectedLogs = List.of(
                "{\"siteId\":1,\"versionCounts\":{\"uid2-sdk-3.0.01\":1,\"uid2-sdk-3.0.02\":1,\"uid2-sdk-3.0.00\":1}}",
                "{\"siteId\":1,\"versionCounts\":{\"uid2-sdk-3.0.01\":2,\"uid2-sdk-3.0.02\":1,\"uid2-sdk-3.0.00\":1}}",
                "{\"siteId\":2,\"versionCounts\":{\"<Not recorded>\":21,\"uid2-sdk-3.0.06\":7,\"uid2-sdk-3.0.07\":8,\"uid2-sdk-3.0.011\":12,\"uid2-sdk-3.0.08\":9,\"uid2-sdk-3.0.010\":11,\"uid2-sdk-3.0.09\":10,\"uid2-sdk-3.0.0single\":1}}"
        );
        var messages = getMessages();
        assertThat(messages).containsAll(expectedLogs);

        testContext.completeNow();
    }
}
