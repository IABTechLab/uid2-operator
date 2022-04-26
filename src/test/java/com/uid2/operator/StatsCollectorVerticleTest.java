package com.uid2.operator;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.uid2.operator.model.StatsCollectorMessageItem;
import com.uid2.operator.monitoring.StatsCollectorVerticle;
import io.vertx.core.Vertx;
import io.vertx.core.eventbus.Message;
import io.vertx.core.logging.Logger;
import io.vertx.junit5.VertxExtension;
import io.vertx.junit5.VertxTestContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.mockito.Mockito.*;


@ExtendWith(VertxExtension.class)
public class StatsCollectorVerticleTest {

    @Mock
    private Logger loggerMock;

    private AtomicInteger statsCollectorRunning;

    private StatsCollectorVerticle verticle;

    @BeforeEach
    void deployVerticle(Vertx vertx, VertxTestContext testContext) throws Throwable {
        statsCollectorRunning = new AtomicInteger(0);
        loggerMock = mock(Logger.class);
        Field field = StatsCollectorVerticle.class.getDeclaredField( "LOGGER" );
        field.setAccessible(true);

        // remove final modifier from field
        Field modifiersField = Field.class.getDeclaredField("modifiers");
        modifiersField.setAccessible(true);
        modifiersField.setInt(field, field.getModifiers() & ~Modifier.FINAL);

        field.set(null, loggerMock);

        verticle = new StatsCollectorVerticle(1000, statsCollectorRunning);
        vertx.deployVerticle(verticle, testContext.succeeding(id -> testContext.completeNow()));
    }


    @Test
    void verticleDeployed(Vertx vertx, VertxTestContext testContext) {
       testContext.completeNow();
    }

    @Test
    void atomicIntDecremented(Vertx vertx, VertxTestContext testContext) throws JsonProcessingException, InterruptedException {
        statsCollectorRunning.incrementAndGet();

        ObjectMapper mapper = new ObjectMapper();
        StatsCollectorMessageItem messageItem = new StatsCollectorMessageItem("test", "https://test.com", "test", 1);

        vertx.eventBus().send("StatsCollector", mapper.writeValueAsString(messageItem));
        testContext.awaitCompletion(1000, TimeUnit.MILLISECONDS);
        assert statsCollectorRunning.get() == 0;
        testContext.completeNow();
    }

    @Test
    void testJSONSerialize(Vertx vertx, VertxTestContext testContext) throws InterruptedException, JsonProcessingException {
        ObjectMapper mapper = new ObjectMapper();
        StatsCollectorMessageItem messageItem = new StatsCollectorMessageItem("/test", "https://test.com", "test", 1);

        vertx.eventBus().send("StatsCollector", mapper.writeValueAsString(messageItem));
        vertx.eventBus().send("StatsCollector", mapper.writeValueAsString(messageItem));
        vertx.eventBus().send("StatsCollector", mapper.writeValueAsString(messageItem));

        messageItem = new StatsCollectorMessageItem("/v1/test", "https://test.com", "test", 1);

        vertx.eventBus().send("StatsCollector", mapper.writeValueAsString(messageItem));
        vertx.eventBus().send("StatsCollector", mapper.writeValueAsString(messageItem));

        testContext.awaitCompletion(2000, TimeUnit.MILLISECONDS);

        String expected =
                "{\"endpoint\":\"test\",\"siteId\":1,\"apiVersion\":\"v1\",\"domainList\":[{\"domain\":\"test.com\",\"count\":2,\"apiContact\":\"test\"}]}\n"
                        + "{\"endpoint\":\"test\",\"siteId\":1,\"apiVersion\":\"v0\",\"domainList\":[{\"domain\":\"test.com\",\"count\":3,\"apiContact\":\"test\"}]}\n";

        String results = verticle.GetEndpointStats();

        assert results.equals(expected);

        testContext.completeNow();
    }
}
