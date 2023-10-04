package com.uid2.operator.benchmark;

import com.uid2.operator.model.*;
import com.uid2.operator.service.IUIDOperatorService;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Mode;

import java.time.Instant;

public class IdentityMapBenchmark {
    private static final IUIDOperatorService uidService;
    private static final UserIdentity[] userIdentities;
    private static int idx = 0;

    static {
        try {
            uidService = BenchmarkCommon.createUidOperatorService();
            userIdentities = BenchmarkCommon.createUserIdentities();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    public MappedIdentity IdentityMapRawThroughput() {
        return uidService.map(userIdentities[(idx++) & 65535], Instant.now());
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    public MappedIdentity IdentityMapWithOptOutThroughput() {
        return uidService.mapIdentity(new MapRequest(userIdentities[(idx++) & 65535], OptoutCheckPolicy.RespectOptOut, Instant.now()));
    }
}
