package com.uid2.operator.model.userIdentity;

import com.uid2.operator.model.IdentityScope;
import com.uid2.operator.model.IdentityType;

import java.time.Instant;
import java.util.Arrays;

// Contains a first level salted computed from Hashed DII (email/phone number) and applying salt to it
public class FirstLevelHashIdentity extends UserIdentity {
    public final byte[] firstLevelHash;

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
}
