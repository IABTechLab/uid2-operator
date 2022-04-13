package com.uid2.operator;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.uid2.operator.monitoring.APIUsageCaptureHandler;
import com.uid2.operator.monitoring.JSONSerializer;
import com.uid2.shared.auth.ClientKey;
import io.vertx.core.MultiMap;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.logging.Logger;
import io.vertx.ext.web.RoutingContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.*;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.HashMap;
import java.util.Objects;

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
        JSONSerializer jsonSerializer = Mockito.mock(JSONSerializer.class);

        ArgumentCaptor<Object[]> valueCapture = ArgumentCaptor.forClass(Object[].class);
        doNothing().when(jsonSerializer).setArray(valueCapture.capture());

        APIUsageCaptureHandler handler = new APIUsageCaptureHandler(1000, Vertx.vertx(), jsonSerializer);

        Logger logger = Mockito.mock(Logger.class);
        Mockito.when(logger.isInfoEnabled()).thenReturn(false);
        setFinalStatic(APIUsageCaptureHandler.class.getDeclaredField("LOGGER"), logger);

        when(routingContext.request()).thenReturn(httpServerRequest);

        when(httpServerRequest.path()).thenReturn("/v1/token/generate");
        when(httpServerRequest.headers()).thenReturn(headers);
        when(headers.get("Referer")).thenReturn("http://test.com");
        handler.handle(routingContext);
        handler.handle(routingContext);
        handler.handle(routingContext);

        when(headers.get("Referer")).thenReturn(null);
        handler.handle(routingContext);

        when(httpServerRequest.path()).thenReturn("/v1/token/refresh");
        when(httpServerRequest.headers()).thenReturn(headers);
        when(headers.get("Referer")).thenReturn("http://test.com");
        handler.handle(routingContext);
        handler.handle(routingContext);

        Thread.sleep(1000);
        when(httpServerRequest.path()).thenReturn("/token/generate");
        handler.handle(routingContext);

        //Lets threads process

        //Call once more to empty threads
        String[] expected = {
                "{\"endpoint\":\"token/generate\",\"siteId\":1,\"apiVersion\":\"v1\",\"domainList\":[{\"domain\":\"test.com\",\"count\":3,\"apiContact\":null},{\"domain\":\"unknown\",\"count\":1,\"apiContact\":null}]}",
                "{\"endpoint\":\"token/refresh\",\"siteId\":1,\"apiVersion\":\"v1\",\"domainList\":[{\"domain\":\"test.com\",\"count\":2,\"apiContact\":null}]}"
        };
        ObjectMapper mapper = new ObjectMapper();
        Object[] results = valueCapture.getValue();
        for (int i = 0; i < results.length; i++) {
            String jsonString = mapper.writeValueAsString(results[i]);
            assert Objects.equals(jsonString, expected[i]);
            System.out.println(jsonString);
        }
    }

    @Test
    public void HandleRequestTestLimit() throws Exception {
        JSONSerializer jsonSerializer = Mockito.mock(JSONSerializer.class);

        ArgumentCaptor<Object[]> valueCapture = ArgumentCaptor.forClass(Object[].class);
        doNothing().when(jsonSerializer).setArray(valueCapture.capture());

        APIUsageCaptureHandler handler = new APIUsageCaptureHandler(5000, Vertx.vertx(), jsonSerializer);

        Logger logger = Mockito.mock(Logger.class);
        Mockito.when(logger.isInfoEnabled()).thenReturn(false);
        setFinalStatic(APIUsageCaptureHandler.class.getDeclaredField("LOGGER"), logger);

        when(routingContext.request()).thenReturn(httpServerRequest);

        when(httpServerRequest.path()).thenReturn("/v1/token/generate");
        when(httpServerRequest.headers()).thenReturn(headers);

        for (int i = 0; i < 1050; i++) {
            when(headers.get("Referer")).thenReturn(String.format("http://test%d.com", i));
            handler.handle(routingContext);
        }

        Thread.sleep(5000);
        when(httpServerRequest.path()).thenReturn("/token/generate");
        handler.handle(routingContext);


        ObjectMapper mapper = new ObjectMapper();
        Object[] results = valueCapture.getValue();

        assert results.length == 1;

        String jsonString = mapper.writeValueAsString(results[0]);
        assert Objects.equals(jsonString.length(), 52963);
    }
}
