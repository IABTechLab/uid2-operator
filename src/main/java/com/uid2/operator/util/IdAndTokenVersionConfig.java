package com.uid2.operator.util;

import com.uid2.shared.model.TokenVersion;

public class IdAndTokenVersionConfig {
    public final TokenVersion advertisingTokenVersion;
    public final TokenVersion refreshTokenVersion;
    public final boolean identityV3Enabled;

    public IdAndTokenVersionConfig(boolean identityV3Enabled, TokenVersion advertisingTokenVersion, TokenVersion refreshTokenVersion) {
        this.advertisingTokenVersion = advertisingTokenVersion;
        this.refreshTokenVersion = refreshTokenVersion;
        this.identityV3Enabled = identityV3Enabled;
    }
}
