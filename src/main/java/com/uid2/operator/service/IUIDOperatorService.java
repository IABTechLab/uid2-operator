package com.uid2.operator.service;

import com.uid2.operator.model.*;
import com.uid2.operator.model.identities.HashedDii;
import com.uid2.shared.model.SaltEntry;
import io.vertx.core.AsyncResult;
import io.vertx.core.Handler;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

public interface IUIDOperatorService {

    TokenGenerateResponse generateIdentity(TokenGenerateRequest request, Duration refreshIdentityAfter, Duration refreshExpiresAfter, Duration identityExpiresAfter);

    TokenRefreshResponse refreshIdentity(TokenRefreshRequest input, Duration refreshIdentityAfter, Duration refreshExpiresAfter, Duration identityExpiresAfter);

    IdentityMapResponseItem mapHashedDii(IdentityMapRequestItem request);

    @Deprecated
    IdentityMapResponseItem map(HashedDii hashedDii, Instant asOf);

    List<SaltEntry> getModifiedBuckets(Instant sinceTimestamp);

    void invalidateTokensAsync(HashedDii hashedDii, Instant asOf, String uidTraceId, Handler<AsyncResult<Instant>> handler);

    boolean advertisingTokenMatches(String advertisingToken, HashedDii hashedDii, Instant asOf);

    Instant getLatestOptoutEntry(HashedDii hashedDii, Instant asOf);
}
