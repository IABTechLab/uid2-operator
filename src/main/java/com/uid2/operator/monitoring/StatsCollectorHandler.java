package com.uid2.operator.monitoring;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.uid2.operator.model.StatsCollectorMessageItem;
import com.uid2.shared.auth.ClientKey;
import com.uid2.shared.middleware.AuthMiddleware;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.ext.web.RoutingContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class StatsCollectorHandler implements Handler<RoutingContext> {
    private static final Logger LOGGER = LoggerFactory.getLogger(StatsCollectorHandler.class);
    private final IStatsCollectorQueue _statCollectorQueue;
    private final Vertx vertx;

    private final ObjectMapper mapper;

    public StatsCollectorHandler(IStatsCollectorQueue _statsQueue, Vertx vert) {
        _statCollectorQueue = _statsQueue;
        vertx = vert;
        mapper = new ObjectMapper();
    }

    @Override
    public void handle(RoutingContext routingContext) {

        routingContext.next();
        assert routingContext != null;

        final String path = routingContext.request().path();
        final String referer = routingContext.request().headers().get("Referer");
        final ClientKey clientKey = (ClientKey) AuthMiddleware.getAuthClient(routingContext);
        final String apiContact = clientKey == null ? null : clientKey.getContact();
        final Integer siteId = clientKey == null ? null : clientKey.getSiteId();
        final StatsCollectorMessageItem messageItem = new StatsCollectorMessageItem(path, referer, apiContact, siteId);

        _statCollectorQueue.enqueue(vertx, messageItem);
    }
}
