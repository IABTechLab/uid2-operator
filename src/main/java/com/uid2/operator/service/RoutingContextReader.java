package com.uid2.operator.service;

import com.uid2.shared.Const;
import com.uid2.shared.auth.IAuthorizable;
import com.uid2.shared.middleware.AuthMiddleware;
import io.vertx.ext.web.RoutingContext;

// Encapsulates non-obvious reading patterns for Routing Context
public class RoutingContextReader {
    private final RoutingContext context;

    public RoutingContextReader(RoutingContext context) {
        this.context = context;
    }

    public Integer getSiteId() {
        final Integer siteId = context.get(Const.RoutingContextData.SiteId);
        if (siteId != null) {
            return siteId;
        }

        final IAuthorizable profile = AuthMiddleware.getAuthClient(context);
        if (profile != null) {
            return profile.getSiteId();
        }

        return null;
    }

    public String getContact() {
        IAuthorizable authClient = AuthMiddleware.getAuthClient(context);
        if (authClient == null) {
            return null;
        }
        return authClient.getContact();
    }

    public String getPath() {
        return context.request().path();
    }

    public String getServiceName() {
        return context.get(SecureLinkValidatorService.SERVICE_NAME, "");
    }

    public String getLinkName() {
        return context.get(SecureLinkValidatorService.LINK_NAME, "");
    }
}
