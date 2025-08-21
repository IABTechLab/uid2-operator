package com.uid2.operator.model;

import java.time.Instant;
import java.util.Arrays;

public class UserIdentity {
    public final IdentityScope identityScope;
    public final IdentityType identityType;
    public final IdentityEnvironment identityEnvironment;
    public final byte[] id;
    public final int privacyBits;
    public final Instant establishedAt;
    public final Instant refreshedAt;

    public UserIdentity(IdentityScope identityScope, IdentityType identityType, IdentityEnvironment identityEnvironment,
                        byte[] id, int privacyBits,
                        Instant establishedAt, Instant refreshedAt) {
        this.identityScope = identityScope;
        this.identityType = identityType;
        this.identityEnvironment = identityEnvironment;
        this.id = id;
        this.privacyBits = privacyBits;
        this.establishedAt = establishedAt;
        this.refreshedAt = refreshedAt;
    }

    public boolean matches(UserIdentity that) {
        return this.identityScope.equals(that.identityScope) &&
                this.identityType.equals(that.identityType) &&
                this.identityEnvironment.equals(that.identityEnvironment) &&
                Arrays.equals(this.id, that.id);
    }
}
