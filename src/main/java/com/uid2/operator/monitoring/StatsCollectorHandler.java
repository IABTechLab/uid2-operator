package com.uid2.operator.monitoring;

import com.uid2.operator.model.StatsCollectorMessageItem;
import com.uid2.shared.Const;
import com.uid2.shared.auth.ClientKey;
import com.uid2.shared.middleware.AuthMiddleware;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.ext.web.RoutingContext;

public class StatsCollectorHandler implements Handler<RoutingContext> {
    private final IStatsCollectorQueue _statCollectorQueue;
    private final Vertx vertx;


    public StatsCollectorHandler(IStatsCollectorQueue _statCollectorQueue, Vertx vertx) {
        this._statCollectorQueue = _statCollectorQueue;
        this.vertx = vertx;
    }

    @Override
    public void handle(RoutingContext routingContext) {
        assert routingContext != null;

        //setAuthClient() has not yet been called, so getAuthClient() would return null. This is resolved by using addBodyEndHandler()
        routingContext.addBodyEndHandler(v -> addStatsMessageToQueue(routingContext));

        routingContext.next(); //previously this next() call was at the top of this function. In V1 APIs, that happened to be an auth handler, but in v2 it was a bodyHandler. Moving next() to the end of the function ensures we don't accidentally depend on a handler that comes later.
    }

    private void addStatsMessageToQueue(RoutingContext routingContext) {
        final String path = routingContext.request().path();
        final String referer = routingContext.request().headers().get("Referer");
        final ClientKey clientKey = (ClientKey) AuthMiddleware.getAuthClient(routingContext);
        final String apiContact = clientKey == null ? null : clientKey.getContact();
        final Integer siteId = clientKey == null ? null : clientKey.getSiteId();

        final StatsCollectorMessageItem messageItem = new StatsCollectorMessageItem(path, referer, apiContact, siteId, getClientVersion(routingContext));

        _statCollectorQueue.enqueue(vertx, messageItem);
    }

    private String getClientVersion(RoutingContext routingContext) {
        String clientVersion = routingContext.request().headers().get(Const.Http.ClientVersionHeader);
        if (clientVersion == null) {
            clientVersion =  !routingContext.queryParam("client").isEmpty() ? routingContext.queryParam("client").get(0) : null;
        }
        return clientVersion;
    }

}
