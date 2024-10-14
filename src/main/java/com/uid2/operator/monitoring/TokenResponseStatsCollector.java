package com.uid2.operator.monitoring;

import com.uid2.operator.model.RefreshResponse;
import com.uid2.operator.vertx.UIDOperatorVerticle;
import com.uid2.shared.model.TokenVersion;
import com.uid2.shared.store.ISiteStore;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Metrics;

public class TokenResponseStatsCollector {
    public enum Endpoint {
        GenerateV0,
        GenerateV1,
        GenerateV2,
        RefreshV0,
        RefreshV1,
        RefreshV2,
        //it's the first version but the endpoint is v2/token/client-generate so we will call it v2
        ClientSideTokenGenerateV2,
    }

    public enum ResponseStatus {
        Success,
        InsufficientUserConsent,
        InvalidUserConsentString,
        OptOut,
        ExpiredToken,
        InvalidToken,
        /* Start of CSTG-related Status */
        MissingParams,
        BadPublicKey,
        BadSubscriptionId,
        InvalidHttpOrigin,
        InvalidAppName,
        BadIV,
        BadPayload, //the actual cstg payload in the JSON request 
        BadJsonPayload, // can't even deserialise the JSON payload 
        PayloadHasNoBody,
        /* End of CSTG-related Status */
        Unknown,
        NoActiveKey,
        Unauthorized
    }

    public enum PlatformType {
        InApp, // Request has the "X-UID2-Client-Version" header, which contains "Android", "ios" or "tvos", typically originating from Android, iOS, or tvOS (Apple TV).
        HasOriginHeader, // Request has the "Origin" header, originating from the web.
        Other // Everything else, such as requests originating from the server side.
    }

    public static void record(ISiteStore siteStore, Integer siteId, Endpoint endpoint, TokenVersion advertisingTokenVersion, ResponseStatus responseStatus, PlatformType platformType) {
        recordInternal(siteStore, siteId, endpoint, responseStatus, advertisingTokenVersion, endpoint == Endpoint.ClientSideTokenGenerateV2, platformType);
    }

    private static void recordInternal(ISiteStore siteStore, Integer siteId, Endpoint endpoint, ResponseStatus responseStatus, TokenVersion advertisingTokenVersion, boolean isCstg, PlatformType platformType) {
        if (siteId == null) return;

        var builder = Counter
                    .builder("uid2_token_response_status_count")
                    .description("Counter for token response statuses").tags(
                            "site_id", String.valueOf(siteId),
                            "site_name", UIDOperatorVerticle.getSiteName(siteStore, siteId),
                            "token_endpoint", String.valueOf(endpoint),
                            "token_response_status", String.valueOf(responseStatus),
                            "advertising_token_version", String.valueOf(advertisingTokenVersion),
                            "cstg", isCstg ? "true" : "false",
                            "platform_type", String.valueOf(platformType));

        builder.register(Metrics.globalRegistry).increment();
    }

    public static void recordRefresh(ISiteStore siteStore, Integer siteId, Endpoint endpoint, RefreshResponse refreshResponse, PlatformType platformType) {
        if (!refreshResponse.isRefreshed()) {
            if (refreshResponse.isOptOut() || refreshResponse.isDeprecated()) {
                recordInternal(siteStore, siteId, endpoint, ResponseStatus.OptOut, refreshResponse.getIdentityResponse().getAdvertisingTokenVersion(), refreshResponse.isCstg(), platformType);
            } else if (refreshResponse.isInvalidToken()) {
                recordInternal(siteStore, siteId, endpoint, ResponseStatus.InvalidToken, refreshResponse.getIdentityResponse().getAdvertisingTokenVersion(), refreshResponse.isCstg(), platformType);
            } else if (refreshResponse.isExpired()) {
                recordInternal(siteStore, siteId, endpoint, ResponseStatus.ExpiredToken, refreshResponse.getIdentityResponse().getAdvertisingTokenVersion(), refreshResponse.isCstg(), platformType);
            }
        } else {
            recordInternal(siteStore, siteId, endpoint, ResponseStatus.Success, refreshResponse.getIdentityResponse().getAdvertisingTokenVersion(), refreshResponse.isCstg(), platformType);
        }
    }
}
