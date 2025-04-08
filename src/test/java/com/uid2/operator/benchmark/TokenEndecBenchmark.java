package com.uid2.operator.benchmark;

import com.uid2.operator.model.*;
import com.uid2.operator.model.identities.HashedDii;
import com.uid2.operator.service.EncryptedTokenEncoder;
import com.uid2.operator.service.IUIDOperatorService;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Mode;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

public class TokenEndecBenchmark {

    private static final IUIDOperatorService uidService;
    private static final HashedDii[] hashedDiiIdentities;
    private static final SourcePublisher publisher;
    private static final EncryptedTokenEncoder encoder;
    private static final TokenGenerateResponse[] generatedTokens;
    private static int idx = 0;

    static {
        try {
            uidService = BenchmarkCommon.createUidOperatorService();
            hashedDiiIdentities = BenchmarkCommon.createHashedDiiIdentities();
            publisher = BenchmarkCommon.createSourcePublisher();
            encoder = BenchmarkCommon.createTokenEncoder();
            generatedTokens = createAdvertisingTokens();
            if (generatedTokens.length < 65536 || hashedDiiIdentities.length < 65536) {
                throw new IllegalStateException("must create more than 65535 test candidates.");
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    static TokenGenerateResponse[] createAdvertisingTokens() {
        List<TokenGenerateResponse> tokens = new ArrayList<>();
        for (int i = 0; i < hashedDiiIdentities.length; i++) {
            tokens.add(
                    uidService.generateIdentity(new TokenGenerateRequest(
                            publisher,
                            hashedDiiIdentities[i],
                            OptoutCheckPolicy.DoNotRespect),
                            Duration.ofSeconds(BenchmarkCommon.REFRESH_IDENTITY_TOKEN_AFTER_SECONDS),
                            Duration.ofSeconds(BenchmarkCommon.REFRESH_TOKEN_EXPIRES_AFTER_SECONDS),
                            Duration.ofSeconds(BenchmarkCommon.IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS))
            );
        }
        return tokens.toArray(new TokenGenerateResponse[tokens.size()]);
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    public TokenGenerateResponse TokenGenerationBenchmark() {
        return uidService.generateIdentity(new TokenGenerateRequest(
                publisher,
                hashedDiiIdentities[(idx++) & 65535],
                OptoutCheckPolicy.DoNotRespect),
                Duration.ofSeconds(BenchmarkCommon.REFRESH_IDENTITY_TOKEN_AFTER_SECONDS),
                Duration.ofSeconds(BenchmarkCommon.REFRESH_TOKEN_EXPIRES_AFTER_SECONDS),
                Duration.ofSeconds(BenchmarkCommon.IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS)
        );
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    public TokenRefreshResponse TokenRefreshBenchmark() {
        return uidService.refreshIdentity(
                encoder.decodeRefreshToken(
                        generatedTokens[(idx++) & 65535].getRefreshToken()),
                Duration.ofSeconds(BenchmarkCommon.REFRESH_IDENTITY_TOKEN_AFTER_SECONDS),
                Duration.ofSeconds(BenchmarkCommon.REFRESH_TOKEN_EXPIRES_AFTER_SECONDS),
                Duration.ofSeconds(BenchmarkCommon.IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS)
        );
    }
}
