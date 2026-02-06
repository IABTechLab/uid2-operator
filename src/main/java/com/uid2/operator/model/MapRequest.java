package com.uid2.operator.model;

import java.time.Instant;

public final class MapRequest {
    public final UserIdentity userIdentity;
    public final Instant asOf;
    public final IdentityEnvironment identityEnvironment;

    public MapRequest(
            UserIdentity userIdentity,
            Instant asOf,
            IdentityEnvironment identityEnvironment) {
        this.userIdentity = userIdentity;
        this.asOf = asOf;
        this.identityEnvironment = identityEnvironment;
    }
}
