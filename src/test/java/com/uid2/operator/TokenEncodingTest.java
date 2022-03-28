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

import com.uid2.operator.model.AdvertisingToken;
import com.uid2.operator.model.RefreshToken;
import com.uid2.operator.model.UserIdentity;
import com.uid2.operator.service.EncodingUtils;
import com.uid2.operator.service.ITokenEncoder;
import com.uid2.operator.service.V2EncryptedTokenEncoder;
import com.uid2.shared.model.EncryptionKey;
import com.uid2.shared.store.IKeyStore;
import com.uid2.shared.store.RotatingKeyStore;
import com.uid2.shared.cloud.EmbeddedResourceStorage;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.unit.TestContext;
import org.junit.Assert;
import org.junit.Test;

import java.security.Security;
import java.time.Instant;

// @RunWith(VertxUnitRunner.class)
public class TokenEncodingTest {

    private final IKeyStore keyStoreInstance;

    public TokenEncodingTest() throws Exception {
        RotatingKeyStore keyStore = new RotatingKeyStore(
            new EmbeddedResourceStorage(Main.class),
            "/com.uid2.core/test/keys/metadata.json");;

        JsonObject m = keyStore.getMetadata();
        keyStore.loadContent(m);

        this.keyStoreInstance = keyStore;
    }

    @Test
    public void testRefreshTokenEncoding() {
        final ITokenEncoder encoder = new V2EncryptedTokenEncoder(keyStoreInstance);
        final Instant now = EncodingUtils.NowUTCMillis();
        final RefreshToken token = new RefreshToken(3,
            now,
            now.plusSeconds(60),
            now.plusSeconds(120),
            new UserIdentity("some-id", 123, 444, now)
        );

        final byte[] encodedBytes = encoder.encode(token);
        final RefreshToken decoded = encoder.decode(encodedBytes);
        Assert.assertEquals(token.getIdentity(), decoded.getIdentity());
        Assert.assertEquals(token.getExpiresAt(), decoded.getExpiresAt());
        Assert.assertEquals(token.getValidTill().plusSeconds(60), decoded.getValidTill());  // encoder adds 1 minute to ValidTill to accommodate communication delay.

        Buffer b = Buffer.buffer(encodedBytes);
        int keyId = b.getInt(25);
        EncryptionKey key = this.keyStoreInstance.getSnapshot().getKey(keyId);
        Assert.assertEquals(Const.Data.RefreshKeySiteId, key.getSiteId());
    }

    @Test
    public void testAdvertisingTokenEncoding() {
        final ITokenEncoder encoder = new V2EncryptedTokenEncoder(keyStoreInstance);
        final Instant now = EncodingUtils.NowUTCMillis();
        final AdvertisingToken token = new AdvertisingToken(4,
            now,
            now.plusSeconds(60),
            new UserIdentity("some-id", 2, 22, now)
        );

        final byte[] encodedBytes = encoder.encode(token);
        final AdvertisingToken decoded = encoder.decodeAdvertisingToken(encodedBytes);

        Assert.assertEquals(token.getExpiresAt(), decoded.getExpiresAt());
        Assert.assertEquals(token.getIdentity(), decoded.getIdentity());

        Buffer b = Buffer.buffer(encodedBytes);
        int keyId = b.getInt(1);
        EncryptionKey key = this.keyStoreInstance.getSnapshot().getKey(keyId);
        Assert.assertEquals(Const.Data.MasterKeySiteId, key.getSiteId());
    }

    // @Test
    public void testFooBarTokens() {

        final String expectedId = "cAtF4kH7suYdvon9OPa8XVpSr2mYMKkcWeJAaJ0Hmrs=";
        final String[][] testCases = new String[][]{
            new String[]{"V1: From Base64 Hash", "AgAAAAPlADr0TFfxLKdMwKkAp51LiBIMaZV16k8GobCYX8ywy6NkYhedXx6QNwctp+kS+mBniR+VHvx9p7sBHrssll9KtEey7953e0Ud3ZjrGAJle1fq3c6R9EdoqzU0Q5z6xnVicv61pZyzmWbNcIYgrjB3UCNK7IzOZy0tldkPcjuPEw=="},
            new String[]{"V1: From Hex Hash", "AgAAAAPx7nJ5SA7Gz2kVHVuQfHDXIZCWnkrUjT5L2xfYbA9xD3z0WMKLZ6RF6xKrAPp04QdZCrLU6ubo5PrteX7GBfywnotHIR08j6ieBg2KV/JLgWzvyr8Tz+0zZYxRVGMO9xsTlLKmOjhAkBVHaRhQtHh2n9rZHhtJ+kj3TkLygujsnA=="},
            new String[]{"V1: From Email", "AgAAAAPwghASss1K7HsWbgx1NwqvHk7Euj0HchfNBRyc/doXvlPCtMX5uhoG1Rl3EwL4ujxQEXT2uWaxnQWXwT1Ei+igibTcKp0GhkWUlchjjWEleQ5LzCObrkPdncA+5k86uWGM06SloXtP/lFXvyZk0CV7NUpQXyAsdUAuLum6wm300g=="},
            new String[]{"V0: From Base64 Hash", "AgAAAANuorJpZCX7ULP8jhqnLUxkO8mykvLP7asMAZOXavVAM+gXvjJBhtMwwep5TvGrwUpeVCqepBSZIiR5jPSq5x44UX3by5FITqs3jfeYYJUl4thgBVOub9HXQmSDyU/i/JGMvj+i7es3qMayelB5Z2VAPG1TR9AhmUgJbM4QdMuNbg=="},
            new String[]{"V0: From Hex Hash", "AgAAAAMPjBIO39Cn9VOGq60m11HtLNc+R/MRuuqPBsM/l+ACBX6tTHGHYsPQ33xT8oM0x5WJjiyRwMEhBPEKZbbA4slMosKV4/xzmEonYznplgyr2thKjVppBUM2GfyxxoW+uG2dlthF6tGKZh4cRKdfpyq9ADkzGzBqwEqntwwxedrn7g=="},
            new String[]{"V0: From Email", "AgAAAAPepHlo7L1pIlU4bUDQU0uAPwOUkPNxrFkpJpqR78PFfXdmUcU2FDOs+/Jp6CdoF2bXlF8WiniovzohEr7MjsobYDYE9Ud/s/b6YJsJ05mQpyCcO/nStazZhbeIiAmclyeHr1TJhpeFypB9G2VT4mKTpG8vdOOzqfWuf+utwJBWnA=="}
        };

        final ITokenEncoder encoder = new V2EncryptedTokenEncoder(keyStoreInstance);
        for (String[] s : testCases) {
            System.out.println("Testing " + s[0] + " with token " + s[1]);
            final AdvertisingToken token = encoder.decodeAdvertisingToken(s[1]);
            Assert.assertEquals(expectedId, token.getIdentity().getId());
        }
    }

    // @Test
    public void testSaltLoader(TestContext ctx) throws Exception {


        /*
        String baseDate = "2021-02-01T00:00:00";

        DateTimeFormatter formatter = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

        LocalDateTime ld = LocalDateTime.parse(baseDate, formatter);
        Instant instant = ld.toInstant(ZoneOffset.UTC);

        final DateTimeFormatter f = DateTimeFormatter.ISO_LOCAL_DATE_TIME.withZone(ZoneId.of("UTC"));
        // final DateTimeFormatter f = DateTimeFormatter.ofPattern("YYYY");
        System.out.println(f.format(instant));

        final RotatingSaltProvider saltProvider = new RotatingSaltProvider(100, new RotatingSaltProvider.LocalSaltStore("/tmp/salts-metadata.txt"));
        saltProvider.Refresh();


        final List<ISaltProvider.SaltEntry> modified = saltProvider.getSnapshot().getModifiedSince(instant);
        System.out.println("Found Entries " + modified.size());

        return;


        /*
        Vertx vertx = Vertx.vertx();
        /

        final RotatingSaltProvider saltProvider = new RotatingSaltProvider(100, new RotatingSaltProvider.LocalSaltStore("/tmp/salts-metadata.txt"));
        final DeploymentOptions deploymentOptions = new DeploymentOptions().setInstances(1);
        vertx.deployVerticle(saltProvider, deploymentOptions, ctx.asyncAssertSuccess());
*/
        /*
        final RotatingSaltProvider saltProvider = new RotatingSaltProvider(100, new RotatingSaltProvider.LocalSaltStore("/tmp/salts-metadata.txt"));
        saltProvider.Refresh();
        int count = 1 << 24;

        final HashMap<String, Integer> counts = new HashMap<String, Integer>();

        final ISaltProvider.ISaltSnapshot snapshot = saltProvider.getSnapshot();

        for (int i = 0; i < count; ++i) {
           final String input = EncodingUtils.toBase64String(EncryptionHelper.getRandomKeyBytes());
           final ISaltProvider.SaltEntry entry = snapshot.getRotatingSalt(input);
           final String bucketId = entry.getHashedId();

           if (counts.containsKey(bucketId)) {
               counts.put(bucketId, counts.get(bucketId) + 1);
           } else {
               counts.put(bucketId, 1);
           }
        }

        FileWriter distros = new FileWriter("/tmp/distros.txt");
        BufferedWriter writer = new BufferedWriter(distros);
        final Set<String> keySet = counts.keySet();
        for (String s : keySet) {
            writer.write(s + "," + counts.get(s));
            writer.newLine();
        }
        writer.flush();
        writer.close();
        distros.close();
        */

    }

    public void testHashing() throws Exception {
        /*
        Hashids hasher = new Hashids("pQV7GjvrpkDuk0VznF6gWTNoxP60cqVZT+O+9hbufLM=", 9);
        System.out.println(hasher.encode(1000000));
        System.out.println(hasher.encode(1999999));
        System.out.println(hasher.encode(2000000));
*/
    }

    @Test
    public void testKeyGen() throws Exception {
        return;
            /*
        String baseDate = "2021-03-01T00:00:00";

        DateTimeFormatter formatter = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

        LocalDateTime ld = LocalDateTime.parse(baseDate, formatter);
        Instant instant = ld.toInstant(ZoneOffset.UTC);




        int count = 1<<20;

        int base = 1000000;

        FileWriter fileWriter = new FileWriter("/tmp/salts.txt");
        BufferedWriter writer = new BufferedWriter(fileWriter);

        for (int i = 0; i < count; ++i) {
            final StringBuilder sb = new StringBuilder();
            int id = base + i;
            sb.append(id);
            sb.append(",");
            sb.append(instant.toEpochMilli());
            sb.append(",");
            sb.append(EncodingUtils.toBase64String(EncryptionHelper.getRandomKeyBytes()));
            writer.newLine();
            writer.write(sb.toString());
        }

        writer.flush();
        writer.close();
        fileWriter.close();

        System.out.println(EncodingUtils.toBase64String(EncryptionHelper.getRandomKeyBytes()));
        System.out.println(EncodingUtils.toBase64String(EncryptionHelper.getRandomKeyBytes()));
        System.out.println(EncodingUtils.toBase64String(EncryptionHelper.getRandomKeyBytes()));
        System.out.println(EncodingUtils.toBase64String(EncryptionHelper.getRandomKeyBytes()));
        System.out.println(EncodingUtils.toBase64String(EncryptionHelper.getRandomKeyBytes()));
        System.out.println(EncodingUtils.toBase64String(EncryptionHelper.getRandomKeyBytes()));
        System.out.println(EncodingUtils.toBase64String(EncryptionHelper.getRandomKeyBytes()));
        System.out.println(EncodingUtils.toBase64String(EncryptionHelper.getRandomKeyBytes()));
        System.out.println(EncodingUtils.toBase64String(EncryptionHelper.getRandomKeyBytes()));
        System.out.println(EncodingUtils.toBase64String(EncryptionHelper.getRandomKeyBytes()));
        System.out.println(EncodingUtils.toBase64String(EncryptionHelper.getRandomKeyBytes()));

             */
    }

    public void testRoundTrip() {
        Security.setProperty("crypto.policy", "unlimited");

        /*
        String masterKey = EncodingUtils.toBase64String(EncryptionHelper.getRandomKeyBytes());
        String siteKey = EncodingUtils.toBase64String(EncryptionHelper.getRandomKeyBytes());
        System.out.println("Master Key = " + masterKey);
        System.out.println("Site Key = " + siteKey);
         */

        Buffer b = Buffer.buffer();
        b.appendByte((byte) 1);
        b.appendInt(23);

        byte[] bts = b.getBytes();

        final byte[] bytes = EncodingUtils.fromBase64("3rkQq/LBqBUPkbxfpFvfMw==");

        final ITokenEncoder encoder = new V2EncryptedTokenEncoder(keyStoreInstance);
        final AdvertisingToken token = new AdvertisingToken(3,
            Instant.now(),
            Instant.now().plusSeconds(60),
            new UserIdentity("foo@bar.com", 123, 444, EncodingUtils.NowUTCMillis())
        );

        System.out.println(EncodingUtils.toBase64String(encoder.encode(token)));

    }

}
