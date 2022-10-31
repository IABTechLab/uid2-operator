package com.uid2.operator.model;

import java.time.Instant;
import java.util.Objects;

public abstract class VersionedToken {
    public final TokenVersion version;
    public final Instant createdAt;
    public final Instant expiresAt;

    public VersionedToken(TokenVersion version, Instant createdAt, Instant expiresAt) {
        this.version = version;
        this.createdAt = createdAt;
        this.expiresAt = expiresAt;
    }
}
