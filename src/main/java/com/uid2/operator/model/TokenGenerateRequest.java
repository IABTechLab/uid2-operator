package com.uid2.operator.model;

import com.uid2.operator.model.identities.HashedDii;
import com.uid2.operator.util.PrivacyBits;

import java.time.Instant;

public final class TokenGenerateRequest {
    public final SourcePublisher sourcePublisher;
    public final HashedDii hashedDii;
    public final OptoutCheckPolicy optoutCheckPolicy;

    public final PrivacyBits privacyBits;
    public final Instant establishedAt;

    public TokenGenerateRequest(
            SourcePublisher sourcePublisher,
            HashedDii hashedDii,
            OptoutCheckPolicy tokenGeneratePolicy,
            PrivacyBits privacyBits,
            Instant establishedAt) {
        this.sourcePublisher = sourcePublisher;
        this.hashedDii = hashedDii;
        this.optoutCheckPolicy = tokenGeneratePolicy;
        this.privacyBits = privacyBits;
        this.establishedAt = establishedAt;
    }

    public TokenGenerateRequest(
            SourcePublisher sourcePublisher,
            HashedDii hashedDii,
            OptoutCheckPolicy tokenGeneratePolicy) {
        this(sourcePublisher, hashedDii, tokenGeneratePolicy, PrivacyBits.DEFAULT, Instant.now());

    }

    public boolean shouldCheckOptOut() {
        return optoutCheckPolicy.equals(OptoutCheckPolicy.RespectOptOut);
    }
}
