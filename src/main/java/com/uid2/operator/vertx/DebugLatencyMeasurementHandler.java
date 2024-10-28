package com.uid2.operator.vertx;

import com.uid2.operator.monitoring.DebugMetricsCollector;
import io.vertx.core.Handler;
import io.vertx.ext.web.RoutingContext;

public class DebugLatencyMeasurementHandler implements Handler<RoutingContext> {
    final String name;

    public DebugLatencyMeasurementHandler(String name) {
        this.name = name;
    }

    public void handle(RoutingContext context) {
        var startTime = DebugMetricsCollector.start();
        context.next();
        DebugMetricsCollector.recordLatency(startTime, this.name);
    }
}
