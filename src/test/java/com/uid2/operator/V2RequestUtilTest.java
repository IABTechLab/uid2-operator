package com.uid2.operator;

import com.uid2.operator.service.V2RequestUtil;
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import com.uid2.shared.IClock;
import com.uid2.shared.auth.ClientKey;
import io.vertx.core.json.JsonObject;
import org.junit.Test;
import org.junit.jupiter.api.AfterEach;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

public class V2RequestUtilTest {
    private static final String LOGGER_NAME = "com.uid2.operator.service.V2RequestUtil";
    private static MemoryAppender memoryAppender;
    private IClock clock = mock(IClock.class);
    private Instant mockNow = Instant.parse("2024-03-20T04:02:46.130Z");

    public void setupMemoryAppender() {
        Logger logger = (Logger)LoggerFactory.getLogger(LOGGER_NAME);
        memoryAppender = new MemoryAppender();
        memoryAppender.setContext((LoggerContext) LoggerFactory.getILoggerFactory());
        logger.setLevel(Level.DEBUG);
        logger.addAppender(memoryAppender);
        memoryAppender.start();
    }

    @AfterEach
    public void close() {
        memoryAppender.reset();
        memoryAppender.stop();
    }

    @Test
    public void testParseRequestWithExpectedJson() {
        when(clock.now()).thenReturn(mockNow);
        String testToken = "AdvertisingTokenmZ4dZgeuXXl6DhoXqbRXQbHlHhA96leN94U1uavZVspwKXlfWETZ3b%2FbesPFFvJxNLLySg4QEYHUAiyUrNncgnm7ppu0mi6wU2CW6hssiuEkKfstbo9XWgRUbWNTM%2BewMzXXM8G9j8Q%3D";
        String testEmailHash = "LdhtUlMQ58ZZy5YUqGPRQw5xUMS5dXG5ocJHYJHbAKI=";
        JsonObject expectedPayload = new JsonObject();
        expectedPayload.put("token", testToken);
        expectedPayload.put("email_hash", testEmailHash);
        // The bodyString was encoded by below json:
        // {
        //    "token": "AdvertisingTokenmZ4dZgeuXXl6DhoXqbRXQbHlHhA96leN94U1uavZVspwKXlfWETZ3b%2FbesPFFvJxNLLySg4QEYHUAiyUrNncgnm7ppu0mi6wU2CW6hssiuEkKfstbo9XWgRUbWNTM%2BewMzXXM8G9j8Q%3D",
        //    "email_hash": "LdhtUlMQ58ZZy5YUqGPRQw5xUMS5dXG5ocJHYJHbAKI="
        //}
        String bodyString = "ATDX9gBKxgQaLwUi9ZDbSqo1b66u55jEN322XSR+aCvOy/c3ZiaVOh8VG22pDUSSNaUqfUwwxxYT0pS9zjW7oVPCeluHU5GCc+6A+LUTIQ8vOR+1CN7ds/61Bp82RzKf5wPABMNtqr1XkoN6d5FU/R0vpxf2hfo1cYYmW0ziCy15pPh17GN2vNTn6YK6g+MAi/dDC7mG+Mxnh9ZaEz+3IetgDPWfp5zHh/T3LWhDAA+2drlDn8KwcQE/TYKh5raR4BDHmhgBUCU6+nymoWruNYxzcII63xMTLMTGzpinNnTL3iBPII9lKRJJ2ZrGjjgMMXi066iaDDpBHH3xY+bAwriU+6GEsE8bveRMwRqT83gmkYp6mn+75Yrpdw==";
        ClientKey ck = new ClientKey(
                "hash",
                "salt",
                "YGdzZw9oM2RzBgB8THMyAEe408lvdfsTsGteaLAGayY=",
                "name",
                "contact",
                mockNow,
                Set.of(),
                113,
                false,
                "key-id"
        );
        V2RequestUtil.V2Request res = V2RequestUtil.parseRequest(bodyString, ck, clock);
        assertEquals(expectedPayload, res.payload);
    }
    @Test
    public void testParseRequestWithNullBody() {
        when(clock.now()).thenReturn(mockNow);
        V2RequestUtil.V2Request res = V2RequestUtil.parseRequest(null, null, clock);
        assertEquals("Invalid body: Body is missing.", res.errorMessage);
    }

    @Test
    public void testParseRequestWithNonBase64Body() {
        when(clock.now()).thenReturn(mockNow);
        V2RequestUtil.V2Request res = V2RequestUtil.parseRequest("test string", null, clock);
        assertEquals("Invalid body: Body is not valid base64.", res.errorMessage);
    }

    @Test
    public void testParseRequestWithTooShortBody() {
        when(clock.now()).thenReturn(mockNow);
        V2RequestUtil.V2Request res = V2RequestUtil.parseRequest("dGVzdA==", null, clock);
        assertEquals("Invalid body: Body too short. Check encryption method.", res.errorMessage);
    }

    @Test
    public void testParseRequestWithMalformedJson() {
        setupMemoryAppender();
        when(clock.now()).thenReturn(Instant.parse("2024-03-20T06:33:15.627Z"));
        // The bodyString was encoded by below json:
        // {
        //    "token": "AdvertisingTokenmZ4dZgeuXXl6DhoXqbRXQbHlHhA96leN94U1uavZVspwKXlfWETZ3b%2FbesPFFvJxNLLySg4QEYHUAiyUrNncgnm7ppu0mi6wU2CW6hssiuEkKfstbo9XWgRUbWNTM%2BewMzXXM8G9j8Q%3D",
        //    "email_hash": "LdhtUlMQ58ZZy5YUqGPRQw5xUMS5dXG5ocJHYJHbAKI=",
        //    test
        //}
        String bodyString = "AWDCc1W2zSIJUFbCF1Ti7FxS9Vq4xywgUxHWm60+aaNIbk9k1c3GLjcezo6ZGx3J9TUEKdCXLVi+t2d4T17acgSZYRhfTUC6OfxEHxzSkhDLviQ6BXqrx0Ute5PWT55FYG5dR8YM8CAUfLuWSxCq4yB+aJ/Sojpl2nmDO7sn7D6K+dAsdCtyciM+8ihxzOb7obhlOhjS5159XqkQTcAQvbfLXi/QJRtFPoDBpwQQZ3TvBFPUvh8uiT0Zb708Xt7zt9NHziqkwAcJWIvnTgLkxBdACpbGGl3mNcwJhHwBM0m9zlSy050yyx/b+U1mJxjj5yqBwaNSzTKiGHs+M1+vhmVD8w7J13Ec+jAUa8rUeN7c61GD/Rh7GndeEBo4WVLvfw==";
        ClientKey ck = new ClientKey(
                "hash",
                "salt",
                "YGdzZw9oM2RzBgB8THMyAEe408lvdfsTsGteaLAGayY=",
                "name",
                "contact",
                mockNow,
                Set.of(),
                113,
                false,
                "key-id"
        );
        V2RequestUtil.V2Request res = V2RequestUtil.parseRequest(bodyString, ck, clock);
        assertEquals("Invalid payload in body: Data is not valid json string.", res.errorMessage);
        assertThat(memoryAppender.countEventsForLogger(LOGGER_NAME)).isEqualTo(1);
        assertThat(memoryAppender.search("[ERROR] Invalid payload in body: Data is not valid json string.").size()).isEqualTo(1);
    }
}
