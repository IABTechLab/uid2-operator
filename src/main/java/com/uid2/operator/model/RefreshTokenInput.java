package com.uid2.operator.model;

import java.time.Instant;

import com.uid2.operator.model.userIdentity.FirstLevelHashIdentity;
import com.uid2.shared.model.TokenVersion;

public class RefreshTokenInput extends VersionedToken {
    public final OperatorIdentity operatorIdentity;
    public final SourcePublisher sourcePublisher;
    public final FirstLevelHashIdentity firstLevelHashIdentity;
    // inherited from the previous refresh token's privacy bits 
    public final int privacyBits;


    public RefreshTokenInput(TokenVersion version, Instant createdAt, Instant expiresAt, OperatorIdentity operatorIdentity,
                             SourcePublisher sourcePublisher, FirstLevelHashIdentity firstLevelHashIdentity, int privacyBits) {
        super(version, createdAt, expiresAt);
        this.operatorIdentity = operatorIdentity;
        this.sourcePublisher = sourcePublisher;
        this.firstLevelHashIdentity = firstLevelHashIdentity;
        this.privacyBits = privacyBits;
    }
}
