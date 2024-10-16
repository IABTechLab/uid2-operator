package com.uid2.operator.model;

import com.uid2.shared.model.TokenVersion;
import io.vertx.core.json.JsonObject;

import java.time.Instant;

// this defines all the fields for the response of the /token/generate and /client/generate endpoints before they are
// jsonified
public class IdentityResponse {
    public static IdentityResponse OptOutIdentityResponse = new IdentityResponse("", null, "", Instant.EPOCH, Instant.EPOCH, Instant.EPOCH);
    private final String advertisingToken;
    private final TokenVersion advertisingTokenVersion;
    private final String refreshToken;
    private final Instant identityExpires;
    private final Instant refreshExpires;
    private final Instant refreshFrom;

    public IdentityResponse(String advertisingToken, TokenVersion advertisingTokenVersion, String refreshToken,
                            Instant identityExpires, Instant refreshExpires, Instant refreshFrom) {
        this.advertisingToken = advertisingToken;
        this.advertisingTokenVersion = advertisingTokenVersion;
        this.refreshToken = refreshToken;
        this.identityExpires = identityExpires;
        this.refreshExpires = refreshExpires;
        this.refreshFrom = refreshFrom;
    }

    public String getAdvertisingToken() {
        return advertisingToken;
    }

    public TokenVersion getAdvertisingTokenVersion() {
        return advertisingTokenVersion;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public Instant getIdentityExpires() {
        return identityExpires;
    }

    public Instant getRefreshExpires() {
        return refreshExpires;
    }

    public Instant getRefreshFrom() {
        return refreshFrom;
    }

    public boolean isOptedOut() {
        return advertisingToken == null || advertisingToken.isEmpty();
    }

    // for v1/v2 token/generate and token/refresh and client/generate (CSTG) endpoints
    public JsonObject toJsonV1() {
        final JsonObject json = new JsonObject();
        json.put("advertising_token", getAdvertisingToken());
        json.put("refresh_token", getRefreshToken());
        json.put("identity_expires", getIdentityExpires().toEpochMilli());
        json.put("refresh_expires", getRefreshExpires().toEpochMilli());
        json.put("refresh_from", getRefreshFrom().toEpochMilli());
        return json;
    }

    // for the original/legacy token/generate and token/refresh endpoint
    public JsonObject toJsonV0() {
        final JsonObject json = new JsonObject();
        json.put("advertisement_token", getAdvertisingToken());
        json.put("advertising_token", getAdvertisingToken());
        json.put("refresh_token", getRefreshToken());

        return json;
    }
}
