// Copyright (c) 2021 The Trade Desk, Inc
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package com.uid2.operator.model;

import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;

public class UserIdentity {
    public final IdentityScope identityScope;
    public final IdentityType identityType;
    public final byte[] id;
    public final int privacyBits;
    public final Instant establishedAt;
    public final Instant refreshedAt;

    public UserIdentity(IdentityScope identityScope, IdentityType identityType, byte[] id, int privacyBits,
                        Instant establishedAt, Instant refreshedAt) {
        this.identityScope = identityScope;
        this.identityType = identityType;
        this.id = id;
        this.privacyBits = privacyBits;
        this.establishedAt = establishedAt;
        this.refreshedAt = refreshedAt;
    }

    public boolean matches(UserIdentity that) {
        return this.identityScope.equals(that.identityScope) &&
                this.identityType.equals(that.identityType) &&
                Arrays.equals(this.id, that.id);
    }
}
