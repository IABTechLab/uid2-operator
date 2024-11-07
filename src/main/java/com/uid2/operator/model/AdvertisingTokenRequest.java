package com.uid2.operator.model;

import java.time.Instant;

import com.uid2.operator.model.userIdentity.RawUidIdentity;
import com.uid2.operator.util.PrivacyBits;
import com.uid2.shared.model.TokenVersion;

// class containing enough data to create a new uid or advertising token
public class AdvertisingTokenRequest extends VersionedToken {
    public final OperatorIdentity operatorIdentity;
    public final SourcePublisher sourcePublisher;
    public final RawUidIdentity rawUidIdentity;
    public final PrivacyBits privacyBits;
    public final Instant establishedAt;

    public AdvertisingTokenRequest(TokenVersion version, Instant createdAt, Instant expiresAt, OperatorIdentity operatorIdentity,
                                   SourcePublisher sourcePublisher, RawUidIdentity rawUidIdentity, PrivacyBits privacyBits,
                                   Instant establishedAt) {
        super(version, createdAt, expiresAt);
        this.operatorIdentity = operatorIdentity;
        this.sourcePublisher = sourcePublisher;
        this.rawUidIdentity = rawUidIdentity;
        this.privacyBits = privacyBits;
        this.establishedAt = establishedAt;
    }
}

