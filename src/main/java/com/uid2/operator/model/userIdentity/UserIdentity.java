package com.uid2.operator.model.userIdentity;

import com.uid2.operator.model.IdentityScope;
import com.uid2.operator.model.IdentityType;

import java.time.Instant;

//base class for all other HshedDii/FirstLevelHash/RawUIDIdentity class and define the basic common fields
public abstract class UserIdentity {

    public final IdentityScope identityScope;
    public final IdentityType identityType;

    public UserIdentity(IdentityScope identityScope, IdentityType identityType) {
        this.identityScope = identityScope;
        this.identityType = identityType;
    }
}
