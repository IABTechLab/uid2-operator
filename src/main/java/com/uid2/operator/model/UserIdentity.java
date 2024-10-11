package com.uid2.operator.model;

import java.time.Instant;

public interface UserIdentity {

    public IdentityScope GetIdentityScope();
    public IdentityType GetIdentityType();
    public Instant GetEstablishedAt();
    public Instant GetIRefreshedAt();
}
