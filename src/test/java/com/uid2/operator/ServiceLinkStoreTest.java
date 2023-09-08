package com.uid2.operator;

import com.uid2.shared.cloud.EmbeddedResourceStorage;
import com.uid2.shared.model.ServiceLink;
import com.uid2.shared.store.CloudPath;
import com.uid2.shared.store.reader.RotatingServiceLinkStore;
import com.uid2.shared.store.scope.GlobalScope;
import io.vertx.core.json.JsonObject;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class ServiceLinkStoreTest {
    @Test
    public void loadFromEmbeddedResourceStorage() throws Exception {
        RotatingServiceLinkStore serviceLinkProvider = new RotatingServiceLinkStore(
                new EmbeddedResourceStorage(Main.class),
                new GlobalScope(new CloudPath("/com.uid2.core/test/service_links/metadata.json")));

        JsonObject m = serviceLinkProvider.getMetadata();
        assertDoesNotThrow(() -> serviceLinkProvider.loadContent(m));

        ServiceLink serviceLink = serviceLinkProvider.getServiceLink(1, "testId1");
        assertNotNull(serviceLink);
        assertEquals("testName1", serviceLink.getName());

        List<ServiceLink> serviceLinks = new ArrayList<>(serviceLinkProvider.getAllServiceLinks());
        assertEquals(2, serviceLinks.size());

        ServiceLink sl1 = new ServiceLink("testId1", 1, 123, "testName1");
        ServiceLink sl2 = new ServiceLink("testId2", 2, 123, "testName2");
        assertTrue(serviceLinks.contains(sl1));
        assertTrue(serviceLinks.contains(sl2));
    }
}
