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
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.slf4j.LoggerFactory;

import java.util.Set;
import java.util.concurrent.TimeUnit;

@ExtendWith(VertxExtension.class)
public class StatsCollectorVerticleTest {
    private static final int MAX_INVALID_PATHS = 5;
    private StatsCollectorVerticle verticle;

    @BeforeEach
    void deployVerticle(Vertx vertx, VertxTestContext testContext) throws Throwable {
        verticle = new StatsCollectorVerticle(1000, MAX_INVALID_PATHS);
        vertx.deployVerticle(verticle, testContext.succeeding(id -> testContext.completeNow()));
    }


    @Test
    void verticleDeployed(Vertx vertx, VertxTestContext testContext) {
       testContext.completeNow();
    }

    @Test
    void testJSONSerializeWithV0AndV1Paths(Vertx vertx, VertxTestContext testContext) throws InterruptedException, JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        StatsCollectorMessageItem messageItem = new StatsCollectorMessageItem("/test", "https://test.com", "test", 1);

        vertx.eventBus().send(Const.Config.StatsCollectorEventBus, mapper.writeValueAsString(messageItem));
        vertx.eventBus().send(Const.Config.StatsCollectorEventBus, mapper.writeValueAsString(messageItem));
        vertx.eventBus().send(Const.Config.StatsCollectorEventBus, mapper.writeValueAsString(messageItem));

        messageItem = new StatsCollectorMessageItem("/v1/test", "https://test.com", "test", 1);

        vertx.eventBus().send(Const.Config.StatsCollectorEventBus, mapper.writeValueAsString(messageItem));
        vertx.eventBus().send(Const.Config.StatsCollectorEventBus, mapper.writeValueAsString(messageItem));

        testContext.awaitCompletion(2000, TimeUnit.MILLISECONDS);

        String expected =
                "{\"endpoint\":\"test\",\"siteId\":1,\"apiVersion\":\"v1\",\"domainList\":[{\"domain\":\"test.com\",\"count\":2,\"apiContact\":\"test\"}]}\n"
                        + "{\"endpoint\":\"test\",\"siteId\":1,\"apiVersion\":\"v0\",\"domainList\":[{\"domain\":\"test.com\",\"count\":3,\"apiContact\":\"test\"}]}\n";

        String results = verticle.getEndpointStats();

        Assertions.assertEquals(results, expected);

        testContext.completeNow();
    }

    @Test
    void testJSONSerializeWithV2AndUnknownPaths(Vertx vertx, VertxTestContext testContext) throws InterruptedException, JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        StatsCollectorMessageItem messageItem = new StatsCollectorMessageItem("/v2/test", "https://test.com", "test", 1);

        vertx.eventBus().send(Const.Config.StatsCollectorEventBus, mapper.writeValueAsString(messageItem));
        vertx.eventBus().send(Const.Config.StatsCollectorEventBus, mapper.writeValueAsString(messageItem));
        vertx.eventBus().send(Const.Config.StatsCollectorEventBus, mapper.writeValueAsString(messageItem));

        messageItem = new StatsCollectorMessageItem("/v2", "https://test.com", "test", 1);

        vertx.eventBus().send(Const.Config.StatsCollectorEventBus, mapper.writeValueAsString(messageItem));
        vertx.eventBus().send(Const.Config.StatsCollectorEventBus, mapper.writeValueAsString(messageItem));

        testContext.awaitCompletion(2000, TimeUnit.MILLISECONDS);

        String expected =
                "{\"endpoint\":\"test\",\"siteId\":1,\"apiVersion\":\"v2\",\"domainList\":[{\"domain\":\"test.com\",\"count\":3,\"apiContact\":\"test\"}]}\n"
                        + "{\"endpoint\":\"v2\",\"siteId\":1,\"apiVersion\":\"unknown\",\"domainList\":[{\"domain\":\"test.com\",\"count\":2,\"apiContact\":\"test\"}]}\n";

        String results = verticle.getEndpointStats();

        Assertions.assertEquals(results, expected);

        testContext.completeNow();
    }

    @Test
    void invalidPathsFiltering(Vertx vertx, VertxTestContext testContext) throws InterruptedException, JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        Set<String> validEndpoints = Endpoints.pathSet();

        for(String endpoint : validEndpoints) {
            StatsCollectorMessageItem messageItem = new StatsCollectorMessageItem(endpoint, "https://test.com", "test", 1);
            vertx.eventBus().send(Const.Config.StatsCollectorEventBus, mapper.writeValueAsString(messageItem));
        }

        for(int i = 0; i < MAX_INVALID_PATHS + 5; i++) {
            StatsCollectorMessageItem messageItem = new StatsCollectorMessageItem("/bad" + i, "https://test.com", "test", 1);
            vertx.eventBus().send(Const.Config.StatsCollectorEventBus, mapper.writeValueAsString(messageItem));
        }

        testContext.awaitCompletion(2000, TimeUnit.MILLISECONDS);

        String results = verticle.getEndpointStats();

        for(String endpoint: validEndpoints) {
            String withoutVersion = endpoint;
            if (endpoint.startsWith("/v1/") || endpoint.startsWith("/v2/")) {
                withoutVersion = endpoint.substring(4);
            } else if (endpoint.startsWith("/")) {
                withoutVersion = endpoint.substring(1);
            }

            String expected = "{\"endpoint\":\"" + withoutVersion + "\",\"siteId\":1,";
            Assertions.assertTrue(results.contains(expected));
        }

        for(int i = 0; i < MAX_INVALID_PATHS; i++) {
            String expected = "{\"endpoint\":\"bad" + i + "\",\"siteId\":1,\"apiVersion\":\"v0\",\"domainList\":[{\"domain\":\"test.com\",\"count\":1,\"apiContact\":\"test\"}]}";
            Assertions.assertTrue(results.contains(expected));
        }
        for(int i = MAX_INVALID_PATHS; i < MAX_INVALID_PATHS + 5; i++) {
            String expected = "{\"endpoint\":\"bad" + i + "\",\"siteId\":1,\"apiVersion\":\"v0\",\"domainList\":[{\"domain\":\"test.com\",\"count\":1,\"apiContact\":\"test\"}]}";
            Assertions.assertFalse(results.contains(expected));
        }

        ListAppender<ILoggingEvent> logWatcher = new ListAppender<>();
        logWatcher.start();
        ((Logger) LoggerFactory.getLogger(StatsCollectorVerticle.class)).addAppender(logWatcher);

        StatsCollectorMessageItem messageItem = new StatsCollectorMessageItem("/triggerSerialize", "https://test.com", "test", 1);
        vertx.eventBus().send(Const.Config.StatsCollectorEventBus, mapper.writeValueAsString(messageItem));

        testContext.awaitCompletion(1000, TimeUnit.MILLISECONDS);

        Assertions.assertTrue(logWatcher.list.get(0).getFormattedMessage().contains("max invalid paths reached; a large number of invalid paths have been requested from authenticated participants"));

        testContext.completeNow();
    }
}
