package com.uid2.operator.util;

import io.vertx.ext.web.RoutingContext;

import java.net.URI;
import java.net.URISyntaxException;

public final class RoutingContextUtil {
    private RoutingContextUtil() {
    }

    public static String getPath(RoutingContext rc) {
        try {
            // If the current route is a known path, extract the full path from the request URI
            if (rc.currentRoute().getPath() != null) {
                return new URI(rc.request().absoluteURI()).getPath();
            }
        } catch (NullPointerException | URISyntaxException ex) {
            // RoutingContextImplBase has a bug: context.currentRoute() throws with NullPointerException when called from bodyEndHandler for StaticHandlerImpl.sendFile()
        }

        return "unknown";
    }
}
