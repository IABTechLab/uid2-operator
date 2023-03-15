package com.uid2.operator.vertx;

import io.vertx.core.Handler;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.ext.web.RoutingContext;
import org.apache.http.impl.EnglishReasonPhraseCatalog;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class GenericFailureHandler implements Handler<RoutingContext> {
    private static final Logger LOGGER = LoggerFactory.getLogger(GenericFailureHandler.class);

    @Override
    public void handle(RoutingContext ctx) {
        // Status code will be 500 for the RuntimeException
        int statusCode = ctx.statusCode();
        HttpServerResponse response = ctx.response();
        String url = ctx.normalizedPath();
        Throwable t = ctx.failure();

        if (t != null) {
            LOGGER.error("URL: [{}] - Error: ", url, t);
        } else {
            LOGGER.error("URL: [{}] - Error: Response code [{}]", url, statusCode);
        }

        response.setStatusCode(statusCode).end(EnglishReasonPhraseCatalog.INSTANCE.getReason(statusCode, null));
    }
}