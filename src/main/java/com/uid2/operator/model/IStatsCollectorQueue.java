package com.uid2.operator.model;

import io.vertx.core.Vertx;

public interface IStatsCollectorQueue {
    void enqueue(Vertx vertx, StatsCollectorMessageItem messageItem);
}
