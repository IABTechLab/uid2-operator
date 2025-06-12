package com.uid2.operator;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.LoggerContext;
import com.uid2.operator.model.IdentityScope;
import com.uid2.operator.model.KeyManager;
import com.uid2.operator.service.V2RequestUtil;
import com.uid2.shared.IClock;
import com.uid2.shared.auth.ClientKey;
import com.uid2.shared.encryption.Random;
import com.uid2.shared.model.KeysetKey;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.web.RequestBody;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrowsExactly;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class V2RequestUtilTest {
    private static final String LOGGER_NAME = "com.uid2.operator.service.V2RequestUtil";
    private static final Instant MOCK_NOW = Instant.parse("2024-03-20T04:02:46.130Z");

    @Mock
    private IClock clock;
    @Mock
    private KeyManager keyManager;
    @Mock
    private KeysetKey refreshKey;
    private MemoryAppender memoryAppender;

    private void setupMemoryAppender() {
        Logger logger = (Logger)LoggerFactory.getLogger(LOGGER_NAME);
        memoryAppender = new MemoryAppender();
        memoryAppender.setContext((LoggerContext) LoggerFactory.getILoggerFactory());
        logger.setLevel(Level.DEBUG);
        logger.addAppender(memoryAppender);
        memoryAppender.start();
    }

    @BeforeEach
    public void setup() {
        setupMemoryAppender();
    }

    @AfterEach
    public void teardown() {
        memoryAppender.reset();
        memoryAppender.stop();
    }

    @Test
    public void testParseRequestWithExpectedJson() {
        when(clock.now()).thenReturn(MOCK_NOW);

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
                MOCK_NOW,
                Set.of(),
                113,
                false,
                "key-id"
        );
        V2RequestUtil.V2Request res = V2RequestUtil.parseRequestAsString(bodyString, ck, clock);

        assertEquals(expectedPayload, res.payload);
    }
    @Test
    public void testParseRequestWithNullBody() {
        when(clock.now()).thenReturn(MOCK_NOW);

        V2RequestUtil.V2Request res = V2RequestUtil.parseRequestAsString(null, null, clock);

        assertEquals("Invalid body: Body is missing.", res.errorMessage);
    }

    @Test
    public void testParseRequestWithNonBase64Body() {
        when(clock.now()).thenReturn(MOCK_NOW);

        V2RequestUtil.V2Request res = V2RequestUtil.parseRequestAsString("test string", null, clock);

        assertEquals("Invalid body: Body is not valid base64.", res.errorMessage);
    }

    @Test
    public void testParseRequestWithTooShortBody() {
        when(clock.now()).thenReturn(MOCK_NOW);

        V2RequestUtil.V2Request res = V2RequestUtil.parseRequestAsString("dGVzdA==", null, clock);

        assertEquals("Invalid body: Body too short. Check encryption method.", res.errorMessage);
    }

    @Test
    public void testParseRequestWithMalformedJson() {
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
                MOCK_NOW,
                Set.of(),
                113,
                false,
                "key-id"
        );
        V2RequestUtil.V2Request res = V2RequestUtil.parseRequestAsString(bodyString, ck, clock);

        assertEquals("Invalid payload in body: Data is not valid json string.", res.errorMessage);
        assertThat(memoryAppender.countEventsForLogger(LOGGER_NAME)).isEqualTo(1);
        assertThat(memoryAppender.search("[ERROR] Invalid payload in body: Data is not valid json string.").size()).isEqualTo(1);
        assertThat(memoryAppender.checkNoThrowableLogged().size()).isEqualTo(1);
    }

    @Test
    public void testHandleRefreshTokenInResponseBody() {
        when(keyManager.getRefreshKey()).thenReturn(refreshKey);
        when(refreshKey.getId()).thenReturn(Integer.MAX_VALUE);
        when(refreshKey.getKeyBytes()).thenReturn(Random.getRandomKeyBytes());

        String response = """
                    {
                        "identity": {
                            "advertising_token": "A4AAABZBgXozOcvdoBLWXaJSltTRG27n1kFegS9IKt-wN8bUPIPKiUXu9gxOzB0CvYprD8-tJNJjYNUy_HegQ1DdWkHwTm9vz9C2PUPtWzZenVy3g5L3hrbD_c7GuA6M6suZAkQGgeRM-7ixjVK2iUKYs5fOgxqzAl21St-7Bm97mgUEoMmg37bW5-X9w3TVs6PAUgSF2DuQmmwVXeKIsmoQZA",
                            "refresh_token": "AAAAFkKfY/PfFkWOByfIqQpP/nWp70ULyurGFQU7CUs5VWWhSgvzFRqXBes5DBqn6GKtwgKH/dF1Cx6Id951RnumXMJ5Oebw4vxQSvtGMNroN1B6HuPZcZiMnvDaTKjCZSAMd6Rc61pZzaQQ7wDKNP9NHNIzRmp7oziVlnEkT/sTJFfZZQPMFjWNqPy2nR0CFg8Zxui5ac6Ix9KEIFXOPM2v1O3kUm5E6x8MJ4vRLclK3NtAbWE3imauSpGSVlqG12hQKEBfN5CbcGRtdQGzdZoWjl8adZQdovufwulg59o8yKrEVPpL7wmoQ5oBaG9GG+FZMx4ttzkS/UlW+uk5qxUopeCRsuOSD/zWAsDDPP+6/FFuIMj+ftASZ7gXVaDraWqD",
                            "identity_expires": 1728595268736,
                            "refresh_expires": 1731186368736,
                            "refresh_from": 1728594668736,
                            "refresh_response_key": "sMRiJivNZJ6msQSvZhsVooG2T/xXTigaFRBPFHCPGQQ="
                        }
                    }
                """;
        JsonObject jsonBody = new JsonObject(response);

        IllegalArgumentException e = assertThrowsExactly(
                IllegalArgumentException.class,
                () -> V2RequestUtil.handleRefreshTokenInResponseBody(jsonBody, keyManager, IdentityScope.UID2));
        assertEquals("Generated refresh token's length=168 is not equal to=388", e.getMessage());
    }
}
