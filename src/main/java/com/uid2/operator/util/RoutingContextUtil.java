package com.uid2.operator.util;

import com.uid2.shared.auth.ClientKey;
import com.uid2.shared.auth.IAuthorizable;
import com.uid2.shared.auth.IAuthorizableProvider;
import com.uid2.shared.middleware.AuthMiddleware;
import io.vertx.ext.web.RoutingContext;

import java.net.URI;
import java.net.URISyntaxException;

public final class RoutingContextUtil {
    private static final String BEARER_TOKEN_PREFIX = "bearer ";
    private static final String UNKNOWN = "unknown";

    private RoutingContextUtil() {
    }

    public static String getApiContact(RoutingContext rc, IAuthorizableProvider authKeyStore) {
        try {
            final String authHeaderValue = rc.request().getHeader("Authorization");
            final String authKey = extractBearerToken(authHeaderValue);
            if (authKey == null) {
                return UNKNOWN;
            }
            final IAuthorizable profile = authKeyStore.get(authKey);
            if (profile == null) {
                return UNKNOWN;
            }
            String apiContact = profile.getContact();
            return apiContact == null ? UNKNOWN : apiContact;
        } catch (Exception ex) {
            return UNKNOWN;
        }
    }

    public static Integer getSiteId(RoutingContext rc) {
        return AuthMiddleware.getAuthClient(ClientKey.class, rc).getSiteId();
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

        return UNKNOWN;
    }

    public static String extractBearerToken(final String headerValue) {
        if (headerValue == null) {
            return null;
        }

        final String v = headerValue.trim();
        if (v.length() < BEARER_TOKEN_PREFIX.length()) {
            return null;
        }

        final String givenPrefix = v.substring(0, BEARER_TOKEN_PREFIX.length());

        if (!BEARER_TOKEN_PREFIX.equalsIgnoreCase(givenPrefix)) {
            return null;
        }
        return v.substring(BEARER_TOKEN_PREFIX.length());
    }
}
