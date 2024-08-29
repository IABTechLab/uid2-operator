package com.uid2.operator.vertx;

import com.uid2.shared.vertx.RequestCapturingHandler;
import io.vertx.core.http.impl.HttpUtils;
import io.vertx.ext.web.RoutingContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DebugRequestCapturingHandler extends RequestCapturingHandler {
    private static final Logger LOGGER = LoggerFactory.getLogger(DebugRequestCapturingHandler.class);

    @Override
    public void handle(RoutingContext context) {
        String uri = context.request().uri();
        String path = uri;
        try {
            String normalized = HttpUtils.normalizePath(uri).split("\\?")[0];
            path = Endpoints.pathSet().contains(normalized) ? normalized : "/unknown";
        } catch (IllegalArgumentException e) {
            path = "/unknown";
        }

        int status = context.request().response().getStatusCode();

        if ((path == null || path.contains("unknown")) && (status >= 200 && status < 300)) {
            LOGGER.error("Unknown path with URI [{}] has a successful 2xx HTTP code [{}]", uri, status);
        }

        super.handle(context);
    }
}
