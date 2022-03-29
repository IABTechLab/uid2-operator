package com.uid2.operator;

import com.uid2.operator.vertx.APIUsageCaptureHandler;
import com.uid2.shared.auth.ClientKey;
import io.vertx.core.MultiMap;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.logging.Logger;
import io.vertx.ext.web.RoutingContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.junit.MockitoJUnitRunner;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.HashMap;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

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
    public void test() throws Exception {
    }

    static void setFinalStatic(Field field, Object newValue) throws Exception {
        field.setAccessible(true);
        Field modifiersField = Field.class.getDeclaredField("modifiers");
        modifiersField.setAccessible(true);
        modifiersField.setInt(field, field.getModifiers() & ~Modifier.FINAL);
        field.set(null, newValue);
    }
    @Test
    public void HandleRequest() throws Exception {
        APIUsageCaptureHandler handler = new APIUsageCaptureHandler(1000);

        Logger logger = Mockito.mock(Logger.class);
        Mockito.when(logger.isInfoEnabled()).thenReturn(false);
        setFinalStatic(APIUsageCaptureHandler.class.getDeclaredField("LOGGER"), logger);

        when(routingContext.request()).thenReturn(httpServerRequest);

        when(httpServerRequest.path()).thenReturn("/v1/token/generate");
        when(httpServerRequest.headers()).thenReturn(headers);

        when(headers.get("Referer")).thenReturn("test.com");

        handler.handle(routingContext);
        handler.handle(routingContext);
        handler.handle(routingContext);

        when(httpServerRequest.path()).thenReturn("/token/generate");
        handler.handle(routingContext);

        //Lets threads process
        Thread.sleep(2000);

        //Call once more to empty threads
        handler.handleJsonSerial(1L);
        verify(logger).debug("{\"endpoint\":\"token/generate\",\"siteId\":1,\"apiVersion\":\"v1\",\"domainList\":" +
                "[{\"domain\":\"test.com\",\"count\":3,\"apiContact\":null}]}");
        verify(logger).debug("{\"endpoint\":\"token/generate\",\"siteId\":1,\"apiVersion\":\"v0\",\"domainList\":" +
                "[{\"domain\":\"test.com\",\"count\":1,\"apiContact\":null}]}");
    }
}
