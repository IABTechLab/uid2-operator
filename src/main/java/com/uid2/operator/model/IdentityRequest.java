package com.uid2.operator.model;

import com.uid2.operator.model.userIdentity.HashedDiiIdentity;
import com.uid2.operator.util.PrivacyBits;

import java.time.Instant;

public final class IdentityRequest {
    public final SourcePublisher sourcePublisher;
    public final HashedDiiIdentity hashedDiiIdentity;
    public final OptoutCheckPolicy optoutCheckPolicy;

    public final int privacyBits;
    public final Instant establishedAt;

    public IdentityRequest(
            SourcePublisher sourcePublisher,
            HashedDiiIdentity hashedDiiIdentity,
            OptoutCheckPolicy tokenGeneratePolicy,
            int privacyBits,
            Instant establishedAt)
    {
        this.sourcePublisher = sourcePublisher;
        this.hashedDiiIdentity = hashedDiiIdentity;
        this.optoutCheckPolicy = tokenGeneratePolicy;
        this.privacyBits = privacyBits;
        this.establishedAt = establishedAt;
    }

    public IdentityRequest(
            SourcePublisher sourcePublisher,
            HashedDiiIdentity hashedDiiIdentity,
            OptoutCheckPolicy tokenGeneratePolicy)
    {
        this(sourcePublisher, hashedDiiIdentity, tokenGeneratePolicy, PrivacyBits.DEFAULT_PRIVACY_BIT_VALUE, Instant.now());

    }

    public boolean shouldCheckOptOut() {
        return optoutCheckPolicy.equals(OptoutCheckPolicy.RespectOptOut);
    }
}
