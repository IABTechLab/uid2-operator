package com.uid2.operator.model;

import java.time.Instant;

import com.uid2.shared.model.TokenVersion;


public abstract class VersionedTokenRequest {
    public final TokenVersion version;
    public final Instant createdAt;
    public final Instant expiresAt;

    public VersionedTokenRequest(TokenVersion version, Instant createdAt, Instant expiresAt) {
        this.version = version;
        this.createdAt = createdAt;
        this.expiresAt = expiresAt;
    }
}
