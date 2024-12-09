package com.uid2.operator.model;

import java.time.Instant;

import com.uid2.operator.model.identities.RawUid;
import com.uid2.operator.util.PrivacyBits;
import com.uid2.shared.model.TokenVersion;

// class containing enough information to create a new uid token (aka advertising token)
public class AdvertisingTokenRequest extends VersionedTokenRequest {
    public final OperatorIdentity operatorIdentity;
    public final SourcePublisher sourcePublisher;
    public final RawUid rawUid;
    public final PrivacyBits privacyBits;
    public final Instant establishedAt;

    public AdvertisingTokenRequest(TokenVersion version, Instant createdAt, Instant expiresAt, OperatorIdentity operatorIdentity,
                                   SourcePublisher sourcePublisher, RawUid rawUid, PrivacyBits privacyBits,
                                   Instant establishedAt) {
        super(version, createdAt, expiresAt);
        this.operatorIdentity = operatorIdentity;
        this.sourcePublisher = sourcePublisher;
        this.rawUid = rawUid;
        this.privacyBits = privacyBits;
        this.establishedAt = establishedAt;
    }
}

