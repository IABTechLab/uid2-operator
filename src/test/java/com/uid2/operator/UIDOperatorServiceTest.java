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

package com.uid2.operator;

import com.uid2.operator.model.IdentityRequest;
import com.uid2.operator.model.IdentityTokens;
import com.uid2.operator.model.RefreshResponse;
import com.uid2.operator.service.EncryptedTokenEncoder;
import com.uid2.operator.service.InputUtil;
import com.uid2.operator.service.UIDOperatorService;
import com.uid2.operator.store.MockOptOutStore;
import com.uid2.shared.store.RotatingKeyStore;
import com.uid2.shared.store.RotatingSaltProvider;
import com.uid2.shared.cloud.EmbeddedResourceStorage;
import io.vertx.ext.unit.Async;
import io.vertx.ext.unit.TestContext;
import io.vertx.ext.unit.junit.VertxUnitRunner;
import junit.framework.TestCase;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.security.Security;

@RunWith(VertxUnitRunner.class)
public class UIDOperatorServiceTest {

    private UIDOperatorService createOperatorService() throws Exception {
        Security.setProperty("crypto.policy", "unlimited");

        RotatingKeyStore keyStore = new RotatingKeyStore(
            new EmbeddedResourceStorage(Main.class),
            "/com.uid2.core/test/keys/metadata.json");
        keyStore.loadContent();

        RotatingSaltProvider saltProvider = new RotatingSaltProvider(
            new EmbeddedResourceStorage(Main.class),
            "/com.uid2.core/test/salts/metadata.json");
        saltProvider.loadContent();

        MockOptOutStore optOutStore = new MockOptOutStore();

        final UIDOperatorService idService = new UIDOperatorService(keyStore,
            optOutStore,
            saltProvider,
            new EncryptedTokenEncoder(keyStore)
        );

        return idService;
    }

    @Test
    public void testIdService(TestContext ctx) throws Exception {
        final UIDOperatorService idService = createOperatorService();
        final String email = "red5550ttd@gmail.com";

        final IdentityTokens tokens = idService.generateIdentity(
            new IdentityRequest(email, 4, 12)
        );
        Assert.assertNotNull(tokens);

        final RefreshResponse refreshResponse = idService.refreshIdentity(tokens.getRefreshToken());
        Assert.assertNotNull(refreshResponse);
        Assert.assertNotNull(refreshResponse.getTokens());

        System.out.println("For Email : " + email + "Token = " + tokens.getTdid());
    }

    @Test
    public void testGenerateAndRefresh(TestContext ctx) throws Exception {
        final UIDOperatorService idService = createOperatorService();
        final String email = "validate@email.com";
        final InputUtil.InputVal inputVal = InputUtil.NormalizeEmail(email);

        final IdentityTokens tokens = idService.generateIdentity(
                new IdentityRequest(inputVal.getIdentityInput(), 4, 12)
        );
        Assert.assertNotNull(tokens);

        Async asyncValidation = ctx.async();
        idService.refreshIdentityAsync(tokens.getRefreshToken(), ar -> {
            ctx.assertTrue(ar.succeeded());
            if (ar.succeeded()) {
                ctx.assertNotEquals(RefreshResponse.Optout, ar.result());
            }
            asyncValidation.complete();
        });
    }

    @Test
    public void testTestOptOutKey(TestContext ctx) throws Exception {
        final UIDOperatorService idService = createOperatorService();
        final String email = "optout@email.com";
        final InputUtil.InputVal inputVal = InputUtil.NormalizeEmail(email);

        final IdentityTokens tokens = idService.generateIdentity(
                new IdentityRequest(inputVal.getIdentityInput(), 4, 12)
        );
        Assert.assertNotNull(tokens);

        Async asyncValidation = ctx.async();
        idService.refreshIdentityAsync(tokens.getRefreshToken(), ar -> {
            ctx.assertTrue(ar.succeeded());
            if (ar.succeeded()) {
                ctx.assertEquals(RefreshResponse.Optout, ar.result());
            }
            asyncValidation.complete();
        });
    }
}
