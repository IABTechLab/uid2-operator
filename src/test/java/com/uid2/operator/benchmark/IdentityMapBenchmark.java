package com.uid2.operator.benchmark;

import com.uid2.operator.model.*;
import com.uid2.operator.model.userIdentity.HashedDiiIdentity;
import com.uid2.operator.service.IUIDOperatorService;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Mode;

import java.time.Instant;

public class IdentityMapBenchmark {
    private static final IUIDOperatorService uidService;
    private static final HashedDiiIdentity[] firstLevelHashIdentities;
    private static int idx = 0;

    static {
        try {
            uidService = BenchmarkCommon.createUidOperatorService();
            firstLevelHashIdentities = BenchmarkCommon.createUserIdentities();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    public RawUidResult IdentityMapRawThroughput() {
        return uidService.map(firstLevelHashIdentities[(idx++) & 65535], Instant.now());
    }

    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    public RawUidResult IdentityMapWithOptOutThroughput() {
        return uidService.mapIdentity(new MapRequest(firstLevelHashIdentities[(idx++) & 65535], OptoutCheckPolicy.RespectOptOut, Instant.now()));
    }
}
