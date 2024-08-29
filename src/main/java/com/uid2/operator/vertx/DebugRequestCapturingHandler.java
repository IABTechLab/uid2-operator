package com.uid2.operator.vertx;

import com.uid2.shared.vertx.RequestCapturingHandler;
import io.vertx.ext.web.RoutingContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DebugRequestCapturingHandler extends RequestCapturingHandler {
    private static final Logger LOGGER = LoggerFactory.getLogger(DebugRequestCapturingHandler.class);

    @Override
    public void handle(RoutingContext context) {
        String path = context.currentRoute().getPath();
        String uri = context.request().uri();
        int status = context.request().response().getStatusCode();

        if (path == null && (status >= 200 && status < 300)) {
            LOGGER.error("Unknown path with URI [{}] has a successful 2xx HTTP code [{}]", uri, status);
        }

        super.handle(context);
    }
}
