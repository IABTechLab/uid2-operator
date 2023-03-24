package com.uid2.operator.monitoring;

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
        RefreshV2
    }

    public enum ResponseStatus {
        Success,
        InsufficientUserConsent,
        InvalidUserConsentString,
        OptOut,
        ExpiredToken,
        InvalidToken
    }

    private static final HashMap<Tuple.Tuple3<Integer, Endpoint, ResponseStatus>, Counter> TokenResponseCounters = new HashMap<>();

    public static void record(int siteId, Endpoint endpoint, ResponseStatus responseStatus) {
        TokenResponseCounters.computeIfAbsent(new Tuple.Tuple3<>(siteId, endpoint, responseStatus), k -> Counter
                .builder("uid2.token_generate_optout")
                .description("Counter for optout response on token generate")
                .tags("site_id", String.valueOf(k.getItem1()), "token_type", String.valueOf(k.getItem2()), "token_response_status", String.valueOf(k.getItem3()))
                .register(Metrics.globalRegistry)).increment();
    }
}
