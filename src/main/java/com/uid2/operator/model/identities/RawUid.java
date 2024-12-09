package com.uid2.operator.model.identities;

import java.util.Arrays;

// A raw UID is stored inside
public record RawUid(IdentityScope identityScope, DiiType diiType, byte[] rawUid) {

    public boolean matches(RawUid that) {
        return this.identityScope.equals(that.identityScope) &&
                this.diiType.equals(that.diiType) &&
                Arrays.equals(this.rawUid, that.rawUid);
    }
}
