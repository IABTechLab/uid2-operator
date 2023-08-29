package com.uid2.operator.monitoring;

import com.uid2.operator.model.RefreshResponse;
import com.uid2.operator.util.Tuple;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Metrics;

import java.util.HashMap;

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
        BadTimestamp,
        InvalidHttpOrigin,
        BadIV,
        BadPayload,
        /* Start of CSTG-related Status */
    }

    private static final HashMap<Tuple.Tuple3<Integer, Endpoint, ResponseStatus>, Counter> TokenResponseCounters = new HashMap<>();

    public static void record(Integer siteId, Endpoint endpoint, ResponseStatus responseStatus) {
        if (siteId == null) return;

        TokenResponseCounters.computeIfAbsent(new Tuple.Tuple3<>(siteId, endpoint, responseStatus), k -> Counter
                .builder("uid2.token_response_status_count")
                .description("Counter for token response statuses")
                .tags("site_id", String.valueOf(k.getItem1()), "token_endpoint", String.valueOf(k.getItem2()), "token_response_status", String.valueOf(k.getItem3()))
                .register(Metrics.globalRegistry)).increment();
    }

    public static void record(Integer siteId, Endpoint endpoint, RefreshResponse r) {
        if (!r.isRefreshed()) {
            if (r.isOptOut() || r.isDeprecated()) {
                TokenResponseStatsCollector.record(siteId, endpoint, TokenResponseStatsCollector.ResponseStatus.OptOut);
            } else if (r.isInvalidToken()) {
                TokenResponseStatsCollector.record(siteId, endpoint, TokenResponseStatsCollector.ResponseStatus.InvalidToken);
            } else if (r.isExpired()) {
                TokenResponseStatsCollector.record(siteId, endpoint, TokenResponseStatsCollector.ResponseStatus.ExpiredToken);
            }
        } else {
            TokenResponseStatsCollector.record(siteId, endpoint, TokenResponseStatsCollector.ResponseStatus.Success);
        }
    }
}
