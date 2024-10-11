package com.uid2.operator.model;

import java.time.Instant;
import java.util.Arrays;

// A raw UID is stored inside
public class RawUidIdentity implements UserIdentity {
    public final IdentityScope identityScope;
    public final IdentityType identityType;
    public final byte[] rawUid;
    public final int privacyBits;
    public final Instant establishedAt;
    public final Instant refreshedAt;

    public RawUidIdentity(IdentityScope identityScope, IdentityType identityType, byte[] rawUid, int privacyBits,
                          Instant establishedAt, Instant refreshedAt) {
        this.identityScope = identityScope;
        this.identityType = identityType;
        this.rawUid = rawUid;
        this.privacyBits = privacyBits;
        this.establishedAt = establishedAt;
        this.refreshedAt = refreshedAt;
    }

    public boolean matches(RawUidIdentity that) {
        return this.identityScope.equals(that.identityScope) &&
                this.identityType.equals(that.identityType) &&
                Arrays.equals(this.rawUid, that.rawUid);
    }

    public IdentityScope GetIdentityScope() { return identityScope; }
    public IdentityType GetIdentityType() { return identityType; }
    public Instant GetEstablishedAt() { return establishedAt; };
    public Instant GetIRefreshedAt() { return refreshedAt; }
}
