package com.uid2.operator.service;

import com.uid2.shared.auth.ClientKey;
import com.uid2.shared.auth.Role;
import com.uid2.shared.middleware.AuthMiddleware;
import com.uid2.shared.model.ServiceLink;
import com.uid2.shared.store.reader.RotatingServiceLinkStore;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

public class SecureLinkValidatorServiceTest {
    @Mock
    private RotatingServiceLinkStore rotatingServiceLinkStore;
    @Mock
    private RoutingContext routingContext;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void validateRequestReturnsTrueWhenServiceIdNotSet() {
        this.setClientKey(0);

        SecureLinkValidatorService service = new SecureLinkValidatorService(this.rotatingServiceLinkStore);
        assertTrue(service.validateRequest(this.routingContext, null));
    }

    @Test
    void validateRequestReturnsTrueWhenLinkIdFound() {
        this.setClientKey(10);
        JsonObject requestJsonObject = new JsonObject();
        requestJsonObject.put(SecureLinkValidatorService.LINK_ID, "999");

        when(this.rotatingServiceLinkStore.getServiceLink(10, "999")).thenReturn(new ServiceLink("999", 10, 100, "testServiceLink"));

        SecureLinkValidatorService service = new SecureLinkValidatorService(this.rotatingServiceLinkStore);
        assertTrue(service.validateRequest(this.routingContext, requestJsonObject));
    }

    @Test
    void validateRequestReturnsFalseWhenLinkIdNotFound() {
        this.setClientKey(10);
        JsonObject requestJsonObject = new JsonObject();
        requestJsonObject.put(SecureLinkValidatorService.LINK_ID, "999");

        when(this.rotatingServiceLinkStore.getServiceLink(10, "999")).thenReturn(null);

        SecureLinkValidatorService service = new SecureLinkValidatorService(this.rotatingServiceLinkStore);
        assertFalse(service.validateRequest(this.routingContext, requestJsonObject));
    }

    private void setClientKey(int serviceId) {
        Map<String, Object> data = new HashMap<>();
        ClientKey key = new ClientKey("", "", "", "", "", "", Instant.now().getEpochSecond(), Set.of(Role.MAPPER), 100, false, serviceId);

        data.put(AuthMiddleware.API_CLIENT_PROP, key);
        when(this.routingContext.data()).thenReturn(data);
    }
}
