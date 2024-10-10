package com.uid2.operator.model;

import com.uid2.shared.model.TokenVersion;

import java.time.Instant;

public class Identity {
    public static Identity LogoutToken = new Identity("", null, "", Instant.EPOCH, Instant.EPOCH, Instant.EPOCH);
    private final String advertisingToken;
    private final TokenVersion advertisingTokenVersion;
    private final String refreshToken;
    private final Instant identityExpires;
    private final Instant refreshExpires;
    private final Instant refreshFrom;

    public Identity(String advertisingToken, TokenVersion advertisingTokenVersion, String refreshToken,
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

    public boolean isEmptyToken() {
        return advertisingToken == null || advertisingToken.isEmpty();
    }
}
