package com.uid2.operator;

import com.uid2.operator.vertx.APIUsageCaptureHandler;
import com.uid2.shared.auth.ClientKey;
import io.vertx.core.MultiMap;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.ext.web.RoutingContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.HashMap;

import static org.mockito.Mockito.when;

public class APIUsageCaptureTest {
    @Mock
    RoutingContext routingContext;
    @Mock
    HttpServerRequest httpServerRequest;
    @Mock
    MultiMap headers;

    @BeforeEach
    void BeforeTest() {
        MockitoAnnotations.openMocks(this);
        ClientKey clientKey = new ClientKey("test").withSiteId(1);
        HashMap<String, Object> data = new HashMap<String, Object>();
        data.put("api-client", clientKey);
        when(routingContext.data()).thenReturn(data);
    }

    @Test
    public void MergeEndpoints() {
        APIUsageCaptureHandler handler = new APIUsageCaptureHandler(false);

        when(routingContext.request()).thenReturn(httpServerRequest);

        when(httpServerRequest.path()).thenReturn("/v1/token/generate");
        when(httpServerRequest.headers()).thenReturn(headers);

        when(headers.get("Referer")).thenReturn("test.com");

        handler.handle(routingContext);
        handler.handle(routingContext);
        handler.handle(routingContext);

        handler.handleJsonSerial(1L);
    }
}
