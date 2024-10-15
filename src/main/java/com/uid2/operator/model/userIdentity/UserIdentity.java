package com.uid2.operator.model.userIdentity;

import com.uid2.operator.model.IdentityScope;
import com.uid2.operator.model.IdentityType;

import java.time.Instant;

//base class for all other HshedDii/FirstLevelHash/RawUIDIdentity class and define the basic common fields
public class UserIdentity {

    public final IdentityScope identityScope;
    public final IdentityType identityType;
    public final int privacyBits;
    public final Instant establishedAt;
    public final Instant refreshedAt;

    public UserIdentity(IdentityScope identityScope, IdentityType identityType, int privacyBits, Instant establishedAt, Instant refreshedAt) {
        this.identityScope = identityScope;
        this.identityType = identityType;
        this.privacyBits = privacyBits;
        this.establishedAt = establishedAt;
        this.refreshedAt = refreshedAt;
    }
}
