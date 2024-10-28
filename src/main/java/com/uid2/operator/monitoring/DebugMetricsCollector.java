package com.uid2.operator.monitoring;

import io.micrometer.core.instrument.Clock;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Metrics;

public class DebugMetricsCollector {
    private static final Clock clock = Clock.SYSTEM;

    public static long start() {
        return now();
    }

    public static long now() {
        return clock.monotonicTime();
    }

    public static void recordLatency(long startTime, String measurementName) {
        var endTime = now();
        var count = Counter
                .builder("uid2_debug_latency_seconds_count")
                .description("Number of times the measurement was made").tags(
                        "name", measurementName);
        var sum = Counter
                .builder("uid2_debug_latency_seconds_sum")
                .description("Total sum of measurements").tags(
                        "name", measurementName);

        count.register(Metrics.globalRegistry).increment();
        sum.register(Metrics.globalRegistry).increment((endTime - startTime) / 1000000000.0);
    }
}
