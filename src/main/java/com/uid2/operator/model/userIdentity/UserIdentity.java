package com.uid2.operator.model.userIdentity;

import com.uid2.operator.model.IdentityScope;
import com.uid2.operator.model.IdentityType;

import java.time.Instant;

//base class for all other HshedDii/FirstLevelHash/RawUIDIdentity class and define the basic common fields
public class UserIdentity {

    public IdentityScope identityScope;
    public IdentityType identityType;
    public int privacyBits;
    public Instant establishedAt;
    public Instant refreshedAt;

    public IdentityScope GetIdentityScope() { return identityScope; }
    public IdentityType GetIdentityType() { return identityType; }
    public Instant GetEstablishedAt() { return establishedAt; };
    public Instant GetIRefreshedAt() { return refreshedAt; }
}
