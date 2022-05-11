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

public class RefreshResponse {

    public static RefreshResponse Invalid = new RefreshResponse(Status.Invalid, IdentityTokens.LogoutToken);
    public static RefreshResponse Optout = new RefreshResponse(Status.Optout, IdentityTokens.LogoutToken);
    public static RefreshResponse Expired = new RefreshResponse(Status.Expired, IdentityTokens.LogoutToken);
    public static RefreshResponse Deprecated = new RefreshResponse(Status.Deprecated, IdentityTokens.LogoutToken);
    private final Status status;
    private final IdentityTokens tokens;

    private RefreshResponse(Status status, IdentityTokens tokens) {
        this.status = status;
        this.tokens = tokens;
    }

    public static RefreshResponse Refreshed(IdentityTokens tokens) {
        return new RefreshResponse(Status.Refreshed, tokens);
    }

    public Status getStatus() {
        return status;
    }

    public IdentityTokens getTokens() {
        return tokens;
    }

    public boolean isRefreshed() {
        return Status.Refreshed.equals(this.status);
    }

    public boolean isOptOut() {
        return Status.Optout.equals(this.status);
    }

    public boolean isInvalidToken() {
        return Status.Invalid.equals(this.status);
    }

    public boolean isDeprecated() {
        return Status.Deprecated.equals(this.status);
    }

    public boolean isExpired() {
        return Status.Expired.equals(this.status);
    }

    public enum Status {
        Refreshed,
        Invalid,
        Optout,
        Expired,
        Deprecated
    }

}
