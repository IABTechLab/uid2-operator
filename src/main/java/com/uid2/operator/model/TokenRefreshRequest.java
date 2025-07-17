package com.uid2.operator.model;

import java.time.Instant;

import com.uid2.operator.model.identities.FirstLevelHash;
import com.uid2.operator.util.PrivacyBits;
import com.uid2.shared.model.TokenVersion;

// class containing enough data to create a new refresh token
public class TokenRefreshRequest extends VersionedTokenRequest {
    public final OperatorIdentity operatorIdentity;
    public final SourcePublisher sourcePublisher;
    public final FirstLevelHash firstLevelHash;
    // by default, inherited from the previous refresh token's privacy bits
    public final PrivacyBits privacyBits;


    public TokenRefreshRequest(TokenVersion version, Instant createdAt, Instant expiresAt, OperatorIdentity operatorIdentity,
                               SourcePublisher sourcePublisher, FirstLevelHash firstLevelHash, PrivacyBits privacyBits) {
        super(version, createdAt, expiresAt);
        this.operatorIdentity = operatorIdentity;
        this.sourcePublisher = sourcePublisher;
        this.firstLevelHash = firstLevelHash;
        this.privacyBits = privacyBits;
    }
}
