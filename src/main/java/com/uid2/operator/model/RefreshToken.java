package com.uid2.operator.model;

import java.time.Instant;
import com.uid2.shared.model.TokenVersion;

public class RefreshToken extends VersionedToken {
    public final OperatorIdentity operatorIdentity;
    public final PublisherIdentity publisherIdentity;
    public final UserIdentity userIdentity;

    public RefreshToken(TokenVersion version, Instant createdAt, Instant expiresAt, OperatorIdentity operatorIdentity,
                        PublisherIdentity publisherIdentity, UserIdentity userIdentity) {
        super(version, createdAt, expiresAt);
        this.operatorIdentity = operatorIdentity;
        this.publisherIdentity = publisherIdentity;
        this.userIdentity = userIdentity;
    }
}
