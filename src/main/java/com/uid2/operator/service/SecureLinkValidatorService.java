package com.uid2.operator.service;

import com.uid2.shared.auth.ClientKey;
import com.uid2.shared.auth.IAuthorizable;
import com.uid2.shared.middleware.AuthMiddleware;
import com.uid2.shared.model.ServiceLink;
import com.uid2.shared.store.reader.RotatingServiceLinkStore;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SecureLinkValidatorService {
    public static final String LINK_ID = "link_id";
    public static final String LINK_NAME = "link_name";
    public static final String SERVICE_NAME = "service_name";
    private static final Logger LOGGER = LoggerFactory.getLogger(SecureLinkValidatorService.class);
    private final RotatingServiceLinkStore rotatingServiceLinkStore;

    public SecureLinkValidatorService(RotatingServiceLinkStore rotatingServiceLinkStore) {
        this.rotatingServiceLinkStore = rotatingServiceLinkStore;
    }

    public boolean validateRequest(RoutingContext rc, JsonObject requestJsonObject) {
        boolean result = true;
        final IAuthorizable profile = AuthMiddleware.getAuthClient(rc);
        if (profile instanceof ClientKey) {
            ClientKey clientKey = (ClientKey) profile;
            if (clientKey.getServiceId() != 0) {
                // For now using the client key, in the future when we have multiple keys, this can be changed to service name
                rc.put(SERVICE_NAME, clientKey.getName());
                // service_id is set in the request, so need to check if the given link_id is linked to this service
                if (this.rotatingServiceLinkStore == null) {
                    // this is an invalid configuration. This operator is not set to validate service links, but has a service Id set.
                    LOGGER.warn("Invalid configuration. Operator not set to validate service links (validate_service_links=false in config), but the calling client has a ServiceId set. ");
                    return false;
                }

                if (requestJsonObject.containsKey(LINK_ID)) {
                    String linkId = requestJsonObject.getString(LINK_ID);
                    ServiceLink serviceLink = this.rotatingServiceLinkStore.getServiceLink(clientKey.getServiceId(), linkId);
                    if (serviceLink == null) {
                        LOGGER.warn("ClientKey has ServiceId set, but LinkId in request was not authorized. ServiceId: {}, LinkId in request: {}", clientKey.getServiceId(), linkId);
                        return false;
                    }
                    rc.put(LINK_NAME, serviceLink.getName());
                }
            }
        }

        return result;
    }
}
