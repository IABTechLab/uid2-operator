package com.uid2.operator.monitoring;

import com.uid2.operator.model.StatsCollectorMessageItem;
import io.vertx.core.Vertx;

public interface IStatsCollectorQueue {
    void enqueue(Vertx vertx, StatsCollectorMessageItem messageItem);
}
