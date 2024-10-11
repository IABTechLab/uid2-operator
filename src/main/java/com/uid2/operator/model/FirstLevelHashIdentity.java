package com.uid2.operator.model;

import java.time.Instant;
import java.util.Arrays;

// Contains a first level salted computed from Hashed DII (email/phone number) and applying salt to it
public class FirstLevelHashIdentity implements UserIdentity {
    public final IdentityScope identityScope;
    public final IdentityType identityType;
    public final byte[] firstLevelHash;
    public final int privacyBits;
    public final Instant establishedAt;
    public final Instant refreshedAt;

    public FirstLevelHashIdentity(IdentityScope identityScope, IdentityType identityType, byte[] firstLevelHash, int privacyBits,
                                  Instant establishedAt, Instant refreshedAt) {
        this.identityScope = identityScope;
        this.identityType = identityType;
        this.firstLevelHash = firstLevelHash;
        this.privacyBits = privacyBits;
        this.establishedAt = establishedAt;
        this.refreshedAt = refreshedAt;
    }

    public boolean matches(FirstLevelHashIdentity that) {
        return this.identityScope.equals(that.identityScope) &&
                this.identityType.equals(that.identityType) &&
                Arrays.equals(this.firstLevelHash, that.firstLevelHash);
    }

    public IdentityScope GetIdentityScope() { return identityScope; }
    public IdentityType GetIdentityType() { return identityType; }
    public Instant GetEstablishedAt() { return establishedAt; };
    public Instant GetIRefreshedAt() { return refreshedAt; }
}
