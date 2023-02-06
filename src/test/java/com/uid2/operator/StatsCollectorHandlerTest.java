package com.uid2.operator;

import com.uid2.operator.model.StatsCollectorMessageItem;
import com.uid2.operator.monitoring.IStatsCollectorQueue;
import com.uid2.operator.monitoring.StatsCollectorHandler;
import com.uid2.shared.auth.ClientKey;
import com.uid2.shared.middleware.AuthMiddleware;
import io.vertx.core.MultiMap;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.web.RoutingContext;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.HashMap;

import static org.mockito.Mockito.*;

@RunWith(MockitoJUnitRunner.class)
public class StatsCollectorHandlerTest {
    @Mock private RoutingContext routingContext;
    @Mock private HttpServerRequest request;
    @Mock private IStatsCollectorQueue statsCollectorQueue;
    @Mock private Vertx vertx;
    private final HashMap<String, Object> routingContextData = new HashMap<>();
    private StatsCollectorHandler handler;

    @Before
    public void setup() {
        handler = new StatsCollectorHandler(statsCollectorQueue, vertx);
        when(routingContext.request()).thenReturn(request);
        when(routingContext.data()).thenReturn(routingContextData);
    }

    @Test public void requestWithClientKey() {
        final ClientKey clientKey = new ClientKey("test-key", "", "test-contact").withSiteId(123);
        AuthMiddleware.setAuthClient(routingContext, clientKey);
        when(request.path()).thenReturn("test-path");
        when(request.headers()).thenReturn(MultiMap.caseInsensitiveMultiMap());

        handler.handle(routingContext);

        final ArgumentCaptor<StatsCollectorMessageItem> messageCaptor = ArgumentCaptor.forClass(StatsCollectorMessageItem.class);
        verify(statsCollectorQueue).enqueue(any(), messageCaptor.capture());

        final StatsCollectorMessageItem messageItem = messageCaptor.getValue();
        Assert.assertEquals("test-path", messageItem.getPath());
        Assert.assertEquals("test-contact", messageItem.getApiContact());
        Assert.assertEquals(null, messageItem.getReferer());
        Assert.assertEquals(Integer.valueOf(123), messageItem.getSiteId());
    }

    @Test public void requestWithoutClientKeyOrReferer() {
        when(request.path()).thenReturn("test-path");
        when(request.headers()).thenReturn(MultiMap.caseInsensitiveMultiMap());

        handler.handle(routingContext);

        final ArgumentCaptor<StatsCollectorMessageItem> messageCaptor = ArgumentCaptor.forClass(StatsCollectorMessageItem.class);
        verify(statsCollectorQueue).enqueue(any(), messageCaptor.capture());

        final StatsCollectorMessageItem messageItem = messageCaptor.getValue();
        Assert.assertEquals("test-path", messageItem.getPath());
        Assert.assertEquals(null, messageItem.getApiContact());
        Assert.assertEquals(null, messageItem.getReferer());
        Assert.assertEquals(null, messageItem.getSiteId());
    }

    @Test public void requestWithReferer() {
        when(request.path()).thenReturn("test-path");
        when(request.headers()).thenReturn(MultiMap.caseInsensitiveMultiMap().add("Referer", "test-referer"));

        handler.handle(routingContext);

        final ArgumentCaptor<StatsCollectorMessageItem> messageCaptor = ArgumentCaptor.forClass(StatsCollectorMessageItem.class);
        verify(statsCollectorQueue).enqueue(any(), messageCaptor.capture());

        final StatsCollectorMessageItem messageItem = messageCaptor.getValue();
        Assert.assertEquals("test-path", messageItem.getPath());
        Assert.assertEquals(null, messageItem.getApiContact());
        Assert.assertEquals("test-referer", messageItem.getReferer());
        Assert.assertEquals(null, messageItem.getSiteId());
    }
}
