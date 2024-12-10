package com.uid2.operator.utilTests;

import com.uid2.operator.model.TokenGenerateResponse;
import com.uid2.shared.model.TokenVersion;
import io.vertx.core.json.JsonObject;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.junit.Assert.*;


public class TokenGenerateResponseTest {
    @Test
    public void doIdentityResponseTest() throws NoSuchAlgorithmException {
        assertEquals(TokenGenerateResponse.OptOutResponse.getAdvertisingToken(), "");
        assertTrue(TokenGenerateResponse.OptOutResponse.isOptedOut());

        TokenGenerateResponse nullAdTokenValue = new TokenGenerateResponse(null, TokenVersion.V4, "refreshToken", null,null,null);
        assertTrue(nullAdTokenValue.isOptedOut());

        Instant identityExpires = Instant.now();
        Instant refreshFrom = identityExpires.plus(5, ChronoUnit.MINUTES);
        Instant refreshExpires = identityExpires.plus(10, ChronoUnit.MINUTES);



        TokenGenerateResponse response1 = new TokenGenerateResponse("adToken", TokenVersion.V3, "refreshToken", identityExpires
                , refreshExpires, refreshFrom);
        assertEquals(response1.getAdvertisingToken(), "adToken");
        assertEquals(response1.getAdvertisingTokenVersion(), TokenVersion.V3);
        assertEquals(response1.getRefreshToken(), "refreshToken");
        assertEquals(response1.getIdentityExpires(), identityExpires);
        assertEquals(response1.getRefreshExpires(), refreshExpires);
        assertEquals(response1.getRefreshFrom(), refreshFrom);

        JsonObject jsonV1 = response1.toJsonV1();
        assertEquals(jsonV1.getString("advertising_token"), response1.getAdvertisingToken());
        assertEquals(jsonV1.getString("refresh_token"), response1.getRefreshToken());
        assertEquals(jsonV1.getLong("refresh_expires").longValue(), response1.getRefreshExpires().toEpochMilli());
        assertEquals(jsonV1.getLong("refresh_from").longValue(), response1.getRefreshFrom().toEpochMilli());

        JsonObject jsonV0 = response1.toJsonV0();
        assertEquals(jsonV0.getString("advertisement_token"), response1.getAdvertisingToken());
        assertEquals(jsonV0.getString("advertising_token"), response1.getAdvertisingToken());
        assertEquals(jsonV0.getString("refresh_token"), response1.getRefreshToken());
    }
}
