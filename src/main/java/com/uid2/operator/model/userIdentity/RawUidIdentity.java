package com.uid2.operator.model.userIdentity;

import com.uid2.operator.model.IdentityScope;
import com.uid2.operator.model.IdentityType;

import java.time.Instant;
import java.util.Arrays;

// A raw UID is stored inside
public class RawUidIdentity extends UserIdentity {
    public final byte[] rawUid;

    public RawUidIdentity(IdentityScope identityScope, IdentityType identityType, byte[] rawUid, int privacyBits,
                          Instant establishedAt, Instant refreshedAt) {
        super(identityScope, identityType, privacyBits, establishedAt, refreshedAt);
        this.rawUid = rawUid;
    }

    public boolean matches(RawUidIdentity that) {
        return this.identityScope.equals(that.identityScope) &&
                this.identityType.equals(that.identityType) &&
                Arrays.equals(this.rawUid, that.rawUid);
    }
}
