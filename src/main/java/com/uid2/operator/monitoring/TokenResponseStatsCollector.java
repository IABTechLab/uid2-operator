package com.uid2.operator.monitoring;

import com.uid2.operator.model.RefreshResponse;
import com.uid2.operator.vertx.UIDOperatorVerticle;
import com.uid2.shared.store.ISiteStore;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Metrics;

import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

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

    private static final Map<TokenResponseKey, Counter> TokenResponseCounters = new ConcurrentHashMap<>();

    public static void record(ISiteStore siteStore, Integer siteId, Endpoint endpoint, ResponseStatus responseStatus) {
        recordInternal(siteStore, siteId, endpoint, responseStatus, endpoint == Endpoint.ClientSideTokenGenerateV2);
    }

    private static void recordInternal(ISiteStore siteStore, Integer siteId, Endpoint endpoint, ResponseStatus responseStatus, boolean isCstg) {
        if (siteId == null) return;

        TokenResponseCounters.computeIfAbsent(new TokenResponseKey(siteId, endpoint, responseStatus, isCstg), k -> {
            var builder = Counter
                    .builder("uid2_token_response_status_count")
                    .description("Counter for token response statuses").tags(
                            "site_id", String.valueOf(siteId),
                            "site_name", UIDOperatorVerticle.getSiteName(siteStore, siteId),
                            "token_endpoint", String.valueOf(endpoint),
                            "token_response_status", String.valueOf(responseStatus),
                            "cstg", isCstg ? "true" : "false");

            return builder.register(Metrics.globalRegistry);
        }).increment();
    }

    public static void recordRefresh(ISiteStore siteStore, Integer siteId, Endpoint endpoint, RefreshResponse refreshResponse) {
        if (!refreshResponse.isRefreshed()) {
            if (refreshResponse.isOptOut() || refreshResponse.isDeprecated()) {
                recordInternal(siteStore, siteId, endpoint, ResponseStatus.OptOut, refreshResponse.isCstg());
            } else if (refreshResponse.isInvalidToken()) {
                recordInternal(siteStore, siteId, endpoint, ResponseStatus.InvalidToken, refreshResponse.isCstg());
            } else if (refreshResponse.isExpired()) {
                recordInternal(siteStore, siteId, endpoint, ResponseStatus.ExpiredToken, refreshResponse.isCstg());
            }
        } else {
            recordInternal(siteStore, siteId, endpoint, ResponseStatus.Success, refreshResponse.isCstg());
        }
    }

    static class TokenResponseKey {
        private final Integer siteId;
        private final Endpoint endpoint;
        private final ResponseStatus responseStatus;
        private final boolean isCstg;

        public TokenResponseKey(Integer siteId, Endpoint endpoint, ResponseStatus responseStatus, boolean isCstg) {
            this.siteId = siteId;
            this.endpoint = endpoint;
            this.responseStatus = responseStatus;
            this.isCstg = isCstg;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            TokenResponseKey that = (TokenResponseKey) o;
            return Objects.equals(siteId, that.siteId) && endpoint == that.endpoint && responseStatus == that.responseStatus && Objects.equals(isCstg, that.isCstg);
        }

        @Override
        public int hashCode() {
            return Objects.hash(siteId, endpoint, responseStatus, isCstg);
        }
    }

}
