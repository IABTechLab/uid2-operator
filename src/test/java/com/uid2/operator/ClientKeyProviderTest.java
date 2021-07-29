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

import com.uid2.operator.service.EncodingUtils;
import com.uid2.shared.auth.RotatingClientKeyProvider;
import com.uid2.shared.cloud.EmbeddedResourceStorage;
import io.vertx.core.json.JsonObject;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import static org.junit.Assume.assumeTrue;

public class ClientKeyProviderTest {
    @Test
    public void generateNewClientKeys() throws NoSuchAlgorithmException {
        if (System.getenv("SLOW_DEV_URANDOM") != null) {
            System.err.println("ignore this test since environment variable SLOW_DEV_URANDOM is set");
            return;
        }
        System.out.println("Java VM property java.security.egd: " + System.getProperty("java.security.egd"));
        SecureRandom random = SecureRandom.getInstanceStrong();
        byte[] bytes = new byte[32];
        for (int i = 0; i < 10; ++i) {
            random.nextBytes(bytes);
            System.out.format("client key: %s\n", EncodingUtils.toBase64String(bytes));
        }
    }

    @Test
    public void loadFromEmbeddedResourceStorage() throws Exception {
        RotatingClientKeyProvider fileProvider = new RotatingClientKeyProvider(
            new EmbeddedResourceStorage(Main.class),
            "/com.uid2.core/test/clients/metadata.json");

        JsonObject m = fileProvider.getMetadata();
        fileProvider.loadContent(m);
    }
}
