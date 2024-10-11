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

    RefreshResponse refreshIdentity(RefreshTokenInput refreshTokenInput);

    MappedIdentityResult mapIdentity(MapRequest request);

    @Deprecated
    MappedIdentityResult map(HashedDiiIdentity hashedDiiIdentity, Instant asOf);

    List<SaltEntry> getModifiedBuckets(Instant sinceTimestamp);

    void invalidateTokensAsync(HashedDiiIdentity hashedDiiIdentity, Instant asOf, Handler<AsyncResult<Instant>> handler);

    boolean advertisingTokenMatches(String advertisingToken, HashedDiiIdentity hashedDiiIdentity, Instant asOf);

    Instant getLatestOptoutEntry(HashedDiiIdentity hashedDiiIdentity, Instant asOf);

    Duration getIdentityExpiryDuration();
}
