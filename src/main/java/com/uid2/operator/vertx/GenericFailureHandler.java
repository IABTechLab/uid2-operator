package com.uid2.operator.vertx;

import com.uid2.shared.auth.IAuthorizable;
import com.uid2.shared.auth.OperatorKey;
import com.uid2.shared.middleware.AuthMiddleware;
import com.uid2.shared.auth.ClientKey;
import io.vertx.core.Handler;
import io.vertx.core.http.HttpClosedException;
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

        String contact = "unknown";
        final ClientKey clientKey = (ClientKey) AuthMiddleware.getAuthClient(ctx);
        if (clientKey != null) {
            contact = clientKey.getContact();
        }

        if (t != null) {
            // Because Vert.x swallows stack traces so cannot log stack trace
            // And we want to ignore HttpClosedException errors as it is (usually) caused by users and no impact
            if (t instanceof HttpClosedException) {
                LOGGER.warn("Ignoring exception - URL: [{}], Participant: [{}] - Error:", url, contact, t);
                response.end();
            } else if (statusCode >= 500 && statusCode < 600) { // 5xx is server error, so error
                LOGGER.error("URL: [{}], Participant: [{}] - Error response code: [{}] - Error:", url, contact, statusCode, t);
            } else if (statusCode >= 400 && statusCode < 500) { // 4xx is user error, so just warn
                LOGGER.warn("URL: [{}], Participant: [{}] - Error response code: [{}] - Error:", url, contact, statusCode, t);
            }
        }

        if (!response.ended() && !response.closed()) {
            response.setStatusCode(statusCode)
                    .end(EnglishReasonPhraseCatalog.INSTANCE.getReason(statusCode, null));
        }
    }
}
