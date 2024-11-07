package com.uid2.operator.vertx;

import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public enum Endpoints {
    OPS_HEALTHCHECK("/ops/healthcheck"),

    V0_KEY_LATEST("/key/latest"),
    V0_TOKEN_GENERATE("/token/generate"),
    V0_TOKEN_REFRESH("/token/refresh"),
    V0_TOKEN_VALIDATE("/token/validate"),
    V0_IDENTITY_MAP("/identity/map"),
    V0_TOKEN_LOGOUT("/token/logout"),

    V1_TOKEN_GENERATE("/v1/token/generate"),
    V1_TOKEN_VALIDATE("/v1/token/validate"),
    V1_TOKEN_REFRESH("/v1/token/refresh"),
    V1_IDENTITY_BUCKETS("/v1/identity/buckets"),
    V1_IDENTITY_MAP("/v1/identity/map"),
    V1_KEY_LATEST("/v1/key/latest"),

    V2_TOKEN_GENERATE("/v2/token/generate"),
    V2_TOKEN_REFRESH("/v2/token/refresh"),
    V2_TOKEN_VALIDATE("/v2/token/validate"),
    V2_IDENTITY_BUCKETS("/v2/identity/buckets"),
    V2_IDENTITY_MAP("/v2/identity/map"),
    V2_KEY_LATEST("/v2/key/latest"),
    V2_KEY_SHARING("/v2/key/sharing"),
    V2_KEY_BIDSTREAM("/v2/key/bidstream"),
    V2_TOKEN_LOGOUT("/v2/token/logout"),
    V2_OPTOUT_STATUS("/v2/optout/status"),
    V2_TOKEN_CLIENTGENERATE("/v2/token/client-generate"),

    EUID_SDK_1_0_0("/static/js/euid-sdk-1.0.0.js"),
    OPENID_SDK_1_0("/static/js/openid-sdk-1.0.js"),
    UID2_ESP_0_0_1A("/static/js/uid2-esp-0.0.1a.js"),
    UID2_SDK_0_0_1A("/static/js/uid2-sdk-0.0.1a.js"),
    UID2_SDK_0_0_1A_SOURCE("/static/js/uid2-sdk-0.0.1a-source.ts"),
    UID2_SDK_0_0_1B("/static/js/uid2-sdk-0.0.1b.js"),
    UID2_SDK_1_0_0("/static/js/uid2-sdk-1.0.0.js"),
    UID2_SDK_2_0_0("/static/js/uid2-sdk-2.0.0.js")
    ;
    private final String path;

    Endpoints(final String path) {
        this.path = path;
    }

    public static Set<String> pathSet() {
        return Stream.of(Endpoints.values()).map(Endpoints::toString).collect(Collectors.toSet());
    }

    @Override
    public String toString() {
        return path;
    }
}
