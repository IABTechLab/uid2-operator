package com.uid2.operator.service;

import com.uid2.shared.auth.ClientKey;
import com.uid2.shared.auth.Role;
import com.uid2.shared.middleware.AuthMiddleware;
import com.uid2.shared.model.ServiceLink;
import com.uid2.shared.store.reader.RotatingServiceLinkStore;
import com.uid2.shared.store.reader.RotatingServiceStore;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RoutingContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SecureLinkValidatorServiceTest {
    @Mock
    private RotatingServiceLinkStore rotatingServiceLinkStore;
    @Mock
    private RotatingServiceStore rotatingServiceStore;
    @Mock
    private RoutingContext routingContext;

    @Test
    void validateRequest_serviceIdNotSet_returnsTrue() {
        this.setClientKey(0);

        SecureLinkValidatorService service = new SecureLinkValidatorService(this.rotatingServiceLinkStore, this.rotatingServiceStore);
        assertTrue(service.validateRequest(this.routingContext, null, Role.MAPPER));
    }

    @Test
    void validateRequest_linkIdFoundAndRoleAllowed_returnsTrue() {
        this.setClientKey(10);
        JsonObject requestJsonObject = new JsonObject();
        requestJsonObject.put(SecureLinkValidatorService.LINK_ID, "999");

        when(this.rotatingServiceLinkStore.getServiceLink(10, "999")).thenReturn(new ServiceLink("999", 10, 100, "testServiceLink", Set.of(Role.MAPPER)));

        SecureLinkValidatorService service = new SecureLinkValidatorService(this.rotatingServiceLinkStore, this.rotatingServiceStore);
        assertTrue(service.validateRequest(this.routingContext, requestJsonObject, Role.MAPPER));
    }

    @Test
    void validateRequest_linkIdNotFound_returnsFalse() {
        this.setClientKey(10);
        JsonObject requestJsonObject = new JsonObject();
        requestJsonObject.put(SecureLinkValidatorService.LINK_ID, "999");

        when(this.rotatingServiceLinkStore.getServiceLink(10, "999")).thenReturn(null);

        SecureLinkValidatorService service = new SecureLinkValidatorService(this.rotatingServiceLinkStore, this.rotatingServiceStore);
        assertFalse(service.validateRequest(this.routingContext, requestJsonObject, Role.MAPPER));
    }

    @Test
    void validateRequest_linkIdFoundLinkDisabled_returnsFalse() {
        this.setClientKey(10);
        JsonObject requestJsonObject = new JsonObject();
        requestJsonObject.put(SecureLinkValidatorService.LINK_ID, "999");

        when(this.rotatingServiceLinkStore.getServiceLink(10, "999")).thenReturn(new ServiceLink("999", 10, 100, "testServiceLink", Set.of(Role.MAPPER), true));

        SecureLinkValidatorService service = new SecureLinkValidatorService(this.rotatingServiceLinkStore, this.rotatingServiceStore);
        assertFalse(service.validateRequest(this.routingContext, requestJsonObject, Role.MAPPER));
    }

    @Test
    void validateRequest_roleNotInServiceLink_returnsFalse() {
        this.setClientKey(10);
        JsonObject requestJsonObject = new JsonObject();
        requestJsonObject.put(SecureLinkValidatorService.LINK_ID, "999");

        when(this.rotatingServiceLinkStore.getServiceLink(10, "999")).thenReturn(new ServiceLink("999", 10, 100, "testServiceLink", Set.of(Role.SHARER, Role.CLIENTKEY_ISSUER)));

        SecureLinkValidatorService service = new SecureLinkValidatorService(this.rotatingServiceLinkStore, this.rotatingServiceStore);
        assertFalse(service.validateRequest(this.routingContext, requestJsonObject, Role.MAPPER));
    }

    private void setClientKey(int serviceId) {
        Map<String, Object> data = new HashMap<>();
        ClientKey key = new ClientKey("", "", "", "", "", Instant.now().toEpochMilli(), Set.of(Role.MAPPER), 100, false, serviceId, "");

        data.put(AuthMiddleware.API_CLIENT_PROP, key);
        when(this.routingContext.data()).thenReturn(data);
    }
}
