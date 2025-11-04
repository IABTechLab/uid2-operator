package com.uid2.operator.service;

import com.uid2.operator.model.*;
import com.uid2.shared.model.SaltEntry;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

public interface IUIDOperatorService {
    IdentityTokens generateIdentity(IdentityRequest request, Duration refreshIdentityAfter, Duration refreshExpiresAfter, Duration identityExpiresAfter);

    RefreshResponse refreshIdentity(RefreshToken token, Duration refreshIdentityAfter, Duration refreshExpiresAfter, Duration identityExpiresAfter, IdentityEnvironment env);

    MappedIdentity mapIdentity(MapRequest request);

    @Deprecated
    MappedIdentity map(UserIdentity userIdentity, Instant asOf, IdentityEnvironment env);

    List<SaltEntry> getModifiedBuckets(Instant sinceTimestamp);

    void invalidateTokensAsync(UserIdentity userIdentity, Instant asOf, String uidTraceId, IdentityEnvironment env,
                               String email, String phone, String clientIp,
                               Handler<AsyncResult<Instant>> handler);

    boolean advertisingTokenMatches(String advertisingToken, UserIdentity userIdentity, Instant asOf, IdentityEnvironment env);
}
