package com.uid2.operator.benchmark;

import com.uid2.operator.model.*;
import com.uid2.operator.service.EncryptedTokenEncoder;
import com.uid2.operator.service.IUIDOperatorService;
import io.vertx.core.json.JsonObject;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Mode;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import static com.uid2.operator.service.UIDOperatorService.*;

public class TokenEndecBenchmark {

    private static final IUIDOperatorService uidService;
    private static final UserIdentity[] userIdentities;
    private static final PublisherIdentity publisher;
    private static final EncryptedTokenEncoder encoder;
    private static final IdentityTokens[] generatedTokens;
    private static int idx = 0;
    private static final JsonObject config;

    static {
        try {
            uidService = BenchmarkCommon.createUidOperatorService();
            userIdentities = BenchmarkCommon.createUserIdentities();
            publisher = BenchmarkCommon.createPublisherIdentity();
            encoder = BenchmarkCommon.createTokenEncoder();
            generatedTokens = createAdvertisingTokens();
            if (generatedTokens.length < 65536 || userIdentities.length < 65536) {
                throw new IllegalStateException("must create more than 65535 test candidates.");
            }
            config = BenchmarkCommon.getConfig();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    static IdentityTokens[] createAdvertisingTokens() {
        List<IdentityTokens> tokens = new ArrayList<>();
        for (int i = 0; i < userIdentities.length; i++) {
            tokens.add(
                    uidService.generateIdentity(
                            new IdentityRequest(
                                publisher,
                                userIdentities[i],
                                OptoutCheckPolicy.DoNotRespect),
                            Duration.ofSeconds(config.getInteger(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS)),
                            Duration.ofSeconds(config.getInteger(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS)),
                            Duration.ofSeconds(config.getInteger(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS))));
        }
        return tokens.toArray(new IdentityTokens[tokens.size()]);
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    public IdentityTokens TokenGenerationBenchmark() {
        return uidService.generateIdentity(new IdentityRequest(
                publisher,
                userIdentities[(idx++) & 65535],
                OptoutCheckPolicy.DoNotRespect),
                Duration.ofSeconds(config.getInteger(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS)),
                Duration.ofSeconds(config.getInteger(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS)),
                Duration.ofSeconds(config.getInteger(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS)));
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    public RefreshResponse TokenRefreshBenchmark() {
        return uidService.refreshIdentity(
                encoder.decodeRefreshToken(
                        generatedTokens[(idx++) & 65535].getRefreshToken()),
                Duration.ofSeconds(config.getInteger(REFRESH_IDENTITY_TOKEN_AFTER_SECONDS)),
                Duration.ofSeconds(config.getInteger(REFRESH_TOKEN_EXPIRES_AFTER_SECONDS)),
                Duration.ofSeconds(config.getInteger(IDENTITY_TOKEN_EXPIRES_AFTER_SECONDS)));
    }
}
