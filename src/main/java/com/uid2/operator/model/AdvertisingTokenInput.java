package com.uid2.operator.model;

import java.time.Instant;
import com.uid2.shared.model.TokenVersion;

public class AdvertisingTokenInput extends VersionedToken {
    public final OperatorIdentity operatorIdentity;
    public final PublisherIdentity publisherIdentity;
    public final RawUidIdentity rawUidIdentity;

    public AdvertisingTokenInput(TokenVersion version, Instant createdAt, Instant expiresAt, OperatorIdentity operatorIdentity,
                                 PublisherIdentity publisherIdentity, RawUidIdentity rawUidIdentity) {
        super(version, createdAt, expiresAt);
        this.operatorIdentity = operatorIdentity;
        this.publisherIdentity = publisherIdentity;
        this.rawUidIdentity = rawUidIdentity;
    }
}

