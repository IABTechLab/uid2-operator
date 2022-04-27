package com.uid2.operator.monitoring;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.uid2.operator.Const;
import com.uid2.operator.model.StatsCollectorMessageItem;
import com.uid2.shared.auth.ClientKey;
import com.uid2.shared.middleware.AuthMiddleware;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Metrics;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.ext.web.RoutingContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.atomic.AtomicInteger;

public class StatsCollectorHandler implements Handler<RoutingContext> {
    private static final Logger LOGGER = LoggerFactory.getLogger(StatsCollectorHandler.class);
   private AtomicInteger _statCollectorCount;
   private final int MAX_STAT_COLLECTORS = 1000;
   private final Vertx vertx;

   private final ObjectMapper mapper;
   private final Counter queueFullCounter;

   public  StatsCollectorHandler(AtomicInteger _statColCount, Vertx vert) {
       _statCollectorCount = _statColCount;
       vertx = vert;
       mapper = new ObjectMapper();
       queueFullCounter = Counter
               .builder("uid2.api_usage_queue_full")
               .description("counter for how many usage messages are dropped because the queue is full")
               .register(Metrics.globalRegistry);
   }

    @Override
    public void handle(RoutingContext routingContext) {

        routingContext.next();
        assert routingContext != null;

        String path = routingContext.request().path();
        String referer = routingContext.request().headers().get("Referer");
        ClientKey clientKey = (ClientKey) AuthMiddleware.getAuthClient(routingContext);
        StatsCollectorMessageItem messageItem = new StatsCollectorMessageItem(path, referer, clientKey.getContact(), clientKey.getSiteId());

        if(_statCollectorCount.get() >= MAX_STAT_COLLECTORS){
            queueFullCounter.increment();
            return;
        }

        try {
            vertx.eventBus().send(Const.Config.StatsCollectorEventBus, mapper.writeValueAsString(messageItem));
            _statCollectorCount.incrementAndGet();
        } catch (JsonProcessingException e) {
            LOGGER.error(e.getMessage(), e);
        }
    }
}
