package com.uid2.operator.model;

import java.time.Instant;

import com.uid2.operator.model.userIdentity.RawUidIdentity;
import com.uid2.operator.util.PrivacyBits;
import com.uid2.shared.model.TokenVersion;

public class AdvertisingTokenInput extends VersionedToken {
    public final OperatorIdentity operatorIdentity;
    public final SourcePublisher sourcePublisher;
    public final RawUidIdentity rawUidIdentity;
    public final PrivacyBits privacyBits;
    public final Instant establishedAt;

    public AdvertisingTokenInput(TokenVersion version, Instant createdAt, Instant expiresAt, OperatorIdentity operatorIdentity,
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

