package com.uid2.operator.service;

import com.uid2.operator.model.*;
import com.uid2.shared.model.SaltEntry;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

public interface IUIDOperatorService {

    Identity generateIdentity(IdentityRequest request);

    RefreshResponse refreshIdentity(RefreshToken refreshToken);

    MappedIdentity mapIdentity(MapRequest request);

    @Deprecated
    MappedIdentity map(UserIdentity userIdentity, Instant asOf);

    List<SaltEntry> getModifiedBuckets(Instant sinceTimestamp);

    void invalidateTokensAsync(UserIdentity userIdentity, Instant asOf, Handler<AsyncResult<Instant>> handler);

    boolean advertisingTokenMatches(String advertisingToken, UserIdentity userIdentity, Instant asOf);

    Instant getLatestOptoutEntry(UserIdentity userIdentity, Instant asOf);

    Duration getIdentityExpiryDuration();
}
