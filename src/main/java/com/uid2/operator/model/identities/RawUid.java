package com.uid2.operator.model.identities;

import com.uid2.operator.model.IdentityScope;
import com.uid2.operator.model.IdentityType;

import java.util.Arrays;

// A raw UID is stored inside
public record RawUid(IdentityScope identityScope, IdentityType identityType, byte[] rawUid) {

    public boolean matches(RawUid that) {
        return this.identityScope.equals(that.identityScope) &&
                this.identityType.equals(that.identityType) &&
                Arrays.equals(this.rawUid, that.rawUid);
    }
}
