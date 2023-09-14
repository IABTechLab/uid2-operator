package com.uid2.operator;

import com.uid2.shared.auth.Role;
import com.uid2.shared.cloud.EmbeddedResourceStorage;
import com.uid2.shared.model.Service;
import com.uid2.shared.store.CloudPath;
import com.uid2.shared.store.reader.RotatingServiceStore;
import com.uid2.shared.store.scope.GlobalScope;
import io.vertx.core.json.JsonObject;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

public class ServiceStoreTest {
    @Test
    public void loadFromEmbeddedResourceStorage() throws Exception {
        RotatingServiceStore serviceProvider = new RotatingServiceStore(
                new EmbeddedResourceStorage(Main.class),
                new GlobalScope(new CloudPath("/com.uid2.core/test/services/metadata.json")));

        JsonObject m = serviceProvider.getMetadata();
        assertDoesNotThrow(() -> serviceProvider.loadContent(m));

        List<Service> services = new ArrayList<>(serviceProvider.getAllServices());
        assertEquals(2, services.size());

        Service service = serviceProvider.getService(2);
        assertNotNull(service);
        assertEquals("testName2", service.getName());

        Service s1 = new Service(1, 123, "testName1", Set.of(Role.GENERATOR));
        Service s2 = new Service(2, 123, "testName2", Set.of(Role.ID_READER));
        assertTrue(services.contains(s1));
        assertTrue(services.contains(s2));

    }
}
