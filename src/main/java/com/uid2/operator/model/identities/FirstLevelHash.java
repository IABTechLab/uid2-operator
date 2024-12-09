package com.uid2.operator.model.identities;

import com.uid2.operator.model.IdentityScope;
import com.uid2.operator.model.IdentityType;

import java.time.Instant;
import java.util.Arrays;

/**
 * Contains a first level salted hash computed from Hashed DII (email/phone number)
 * @param establishedAt for brand new token generation, it should be the time it is generated if the first level hash is from token/refresh call, it will be when the raw UID was originally created in the earliest token generation
 */
public record FirstLevelHash(IdentityScope identityScope, IdentityType identityType, byte[] firstLevelHash,
                             Instant establishedAt) {

    // explicitly not checking establishedAt - this is only for making sure the first level hash matches a new input
    public boolean matches(FirstLevelHash that) {
        return this.identityScope.equals(that.identityScope) &&
                this.identityType.equals(that.identityType) &&
                Arrays.equals(this.firstLevelHash, that.firstLevelHash);
    }
}
