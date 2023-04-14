package com.uid2.operator;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.uid2.operator.model.StatsCollectorMessageItem;
import com.uid2.operator.monitoring.StatsCollectorVerticle;
import io.vertx.core.Vertx;
import org.slf4j.Logger;
import io.vertx.junit5.VertxExtension;
import io.vertx.junit5.VertxTestContext;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.concurrent.TimeUnit;

import static org.mockito.Mockito.*;

@ExtendWith(VertxExtension.class)
public class StatsCollectorVerticleTest {
    @Mock
    private Logger loggerMock;

    private StatsCollectorVerticle verticle;

    @BeforeEach
    void deployVerticle(Vertx vertx, VertxTestContext testContext) throws Throwable {
        loggerMock = mock(Logger.class);
        Field field = StatsCollectorVerticle.class.getDeclaredField("LOGGER");
        field.setAccessible(true);

        // remove final modifier from field
        Field modifiersField = Field.class.getDeclaredField("modifiers");
        modifiersField.setAccessible(true);
        modifiersField.setInt(field, field.getModifiers() & ~Modifier.FINAL);

        field.set(null, loggerMock);

        verticle = new StatsCollectorVerticle(1000);
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
}
