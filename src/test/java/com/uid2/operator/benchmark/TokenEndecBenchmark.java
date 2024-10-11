package com.uid2.operator.benchmark;

import com.uid2.operator.model.*;
import com.uid2.operator.service.EncryptedTokenEncoder;
import com.uid2.operator.service.IUIDOperatorService;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Mode;

import java.util.ArrayList;
import java.util.List;

public class TokenEndecBenchmark {

    private static final IUIDOperatorService uidService;
    private static final HashedDiiIdentity[] userIdentities;
    private static final SourcePublisher publisher;
    private static final EncryptedTokenEncoder encoder;
    private static final Identity[] generatedTokens;
    private static int idx = 0;

    static {
        try {
            uidService = BenchmarkCommon.createUidOperatorService();
            userIdentities = BenchmarkCommon.createUserIdentities();
            publisher = BenchmarkCommon.createSourcePublisher();
            encoder = BenchmarkCommon.createTokenEncoder();
            generatedTokens = createAdvertisingTokens();
            if (generatedTokens.length < 65536 || userIdentities.length < 65536) {
                throw new IllegalStateException("must create more than 65535 test candidates.");
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    static Identity[] createAdvertisingTokens() {
        List<Identity> tokens = new ArrayList<>();
        for (int i = 0; i < userIdentities.length; i++) {
            tokens.add(
                    uidService.generateIdentity(new IdentityRequest(
                            publisher,
                            userIdentities[i],
                            OptoutCheckPolicy.DoNotRespect)));
        }
        return tokens.toArray(new Identity[tokens.size()]);
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    public Identity TokenGenerationBenchmark() {
        return uidService.generateIdentity(new IdentityRequest(
                publisher,
                userIdentities[(idx++) & 65535],
                OptoutCheckPolicy.DoNotRespect));
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    public RefreshResponse TokenRefreshBenchmark() {
        return uidService.refreshIdentity(
                encoder.decodeRefreshToken(
                        generatedTokens[(idx++) & 65535].getRefreshToken()));
    }
}
