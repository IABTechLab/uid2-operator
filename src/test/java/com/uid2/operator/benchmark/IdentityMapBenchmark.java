package com.uid2.operator.benchmark;

import com.uid2.operator.model.*;
import com.uid2.operator.model.identities.HashedDii;
import com.uid2.operator.service.IUIDOperatorService;
import com.uid2.operator.service.V2RequestUtil;
import com.uid2.operator.vertx.V2PayloadHandler;
import com.uid2.shared.InstantClock;
import com.uid2.shared.Utils;
import com.uid2.shared.auth.ClientKey;
import com.uid2.shared.auth.Role;
import com.uid2.shared.encryption.AesGcm;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.json.JsonObject;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;

public class IdentityMapBenchmark {
    private static final IUIDOperatorService uidService;
    private static final HashedDii[] hashedDiiIdentities;
    private static int idx = 0;

    static {
        try {
            uidService = BenchmarkCommon.createUidOperatorService();
            hashedDiiIdentities = BenchmarkCommon.createHashedDiiIdentities();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @State(Scope.Thread)
    public static class PayloadState {
        @Param({"100", "1000", "10000"})
        int numRecords;

        Buffer payloadBinary;
        String payloadNone;

        private static final ClientKey clientKey = new ClientKey(
                "FIUDeEqA+O2hW7PXdAJI/NAnJleHX+6QU46avhal5Wy4th0ZEKvG5eoFk8CFvqxGkMFlHwGG+DWTU+ZdwiHdQg==",
                "RvCHAXUo/1pR3Nun5HuzcRJvlC7vT6gZMmsGPzyOONA=",
                "DzBzbjTJcYL0swDtFs2krRNu+g1Eokm2tBU4dEuD0Wk=",
                "test",
                Instant.now(),
                Set.of(Role.MAPPER, Role.GENERATOR, Role.ID_READER, Role.SHARER, Role.OPTOUT),
                999,
                "UID2-C-L-999-fCXrM"
        );
        static Instant now = Instant.now();
        static byte[] nonce = com.uid2.shared.encryption.Random.getBytes(8);
        private static final Random RANDOM = new Random();


        @Setup
        public void setup() {
            this.payloadBinary = Buffer.buffer(createEncryptedPayload(this.numRecords));
            this.payloadNone = Utils.toBase64String(createEncryptedPayload(this.numRecords));
        }

        private static String randomEmail() {
            return "email_" + Math.abs(RANDOM.nextLong()) + "@example.com";
        }

        private static String randomPhoneNumber() {
            // Phone numbers with 15 digits are technically valid but are not used in any country
            return "+" + String.format("%015d", Math.abs(RANDOM.nextLong() % 1_000_000_000_000_000L));
        }

        private static String randomHash() {
            // This isn't really a hashed DII but looks like one ot UID2
            byte[] randomBytes = new byte[32];
            RANDOM.nextBytes(randomBytes);
            return Base64.getEncoder().encodeToString(randomBytes);
        }

        private static JsonObject createDII(int numRecords) {
            JsonObject dii = new JsonObject();
            List<String> emails = new ArrayList<>();
            List<String> phones = new ArrayList<>();
            List<String> emailHashes = new ArrayList<>();
            List<String> phoneHashes = new ArrayList<>();
            for (int i = 0; i < numRecords; i++) {
                emails.add(randomEmail());
                phones.add(randomPhoneNumber());
                emailHashes.add(randomHash());
                phoneHashes.add(randomHash());
            }
            dii.put("email", emails);
            dii.put("email_hash", emailHashes);
            dii.put("phones", phones);
            dii.put("phone_hash", phoneHashes);
            return dii;
        }

        private static byte[] createEncryptedPayload(int numRecords) {
            Buffer b = Buffer.buffer();
            b.appendLong(now.toEpochMilli());
            b.appendLong(new BigInteger(nonce).longValue());

            b.appendBytes(createDII(numRecords).encode().getBytes(StandardCharsets.UTF_8));

            Buffer bufBody = Buffer.buffer();
            bufBody.appendByte((byte) 1);
            byte[] payload = b.getBytes();

            bufBody.appendBytes(AesGcm.encrypt(payload, clientKey.getSecretBytes()));

            return bufBody.getBytes();
        }
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    public IdentityMapResponseItem IdentityMapRawThroughput() {
        return uidService.map(hashedDiiIdentities[(idx++) & 65535], Instant.now());
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    public IdentityMapResponseItem IdentityMapWithOptOutThroughput() {
        return uidService.mapHashedDii(new IdentityMapRequestItem(hashedDiiIdentities[(idx++) & 65535], OptoutCheckPolicy.RespectOptOut, Instant.now()));
    }

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    @Fork(2)
    @Warmup(iterations = 3, time = 1, timeUnit = TimeUnit.SECONDS)
    @Measurement(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)
    public void decompressionBenchmarkingBinary(PayloadState state, Blackhole bh) {
        var data = V2RequestUtil.parseRequestAsBuffer(state.payloadBinary, PayloadState.clientKey, new InstantClock());
        bh.consume(data);
    }

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    @Fork(2)
    @Warmup(iterations = 3, time = 1, timeUnit = TimeUnit.SECONDS)
    @Measurement(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)
    public void decompressionBenchmarkingNone(PayloadState state, Blackhole bh) {
        var data = V2RequestUtil.parseRequestAsString(state.payloadNone, PayloadState.clientKey, new InstantClock());
        bh.consume(data);
    }

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    @Fork(2)
    @Warmup(iterations = 3, time = 1, timeUnit = TimeUnit.SECONDS)
    @Measurement(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)
    public void compressionBenchmarkingBinary(PayloadState state, Blackhole bh) {
        var data = V2PayloadHandler.encryptResponse(PayloadState.nonce, PayloadState.createDII(state.numRecords), PayloadState.clientKey.getSecretBytes());
        bh.consume(data);
    }

    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    @Fork(2)
    @Warmup(iterations = 3, time = 1, timeUnit = TimeUnit.SECONDS)
    @Measurement(iterations = 5, time = 1, timeUnit = TimeUnit.SECONDS)
    public void compressionBenchmarkingNone(PayloadState state, Blackhole bh) {
        var data = V2PayloadHandler.encryptResponse(PayloadState.nonce, PayloadState.createDII(state.numRecords), PayloadState.clientKey.getSecretBytes());
        bh.consume(data);
    }
}
