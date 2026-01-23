package com.uid2.operator.service;

import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.Timer;
import io.vertx.core.Future;
import io.vertx.core.Vertx;
import io.vertx.core.WorkerExecutor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

public class ComputePoolService {
    private static final Logger LOGGER = LoggerFactory.getLogger(ComputePoolService.class);

    private static final String POOL_NAME = "compute";
    private static final String METRIC_PREFIX = "uid2_compute_pool_";

    private final WorkerExecutor workerExecutor;

    // Queue length: incremented on queue, decremented on completion
    // since Vert.x worker executor doesn't expose queue length
    private final AtomicLong queueLength = new AtomicLong(0);

    // Prometheus histogram for queue wait time (time between queued and dispatched)
    private final Timer queueWaitTimer;

    // Prometheus gauge for queue length
    private final Gauge queueLengthGauge;

    /**
     * Creates a ComputePoolService with default pool size (available processors - 2, minimum 1).
     *
     * @param vertx the Vert.x instance
     */
    public ComputePoolService(Vertx vertx) {
        this(vertx, Math.max(1, Runtime.getRuntime().availableProcessors() - 2));
    }

    /**
     * Creates a ComputePoolService with a specified pool size.
     *
     * @param vertx    the Vert.x instance
     * @param poolSize the number of worker threads in the pool
     */
    public ComputePoolService(Vertx vertx, int poolSize) {
        this.workerExecutor = vertx.createSharedWorkerExecutor(POOL_NAME, poolSize);

        // Histogram buckets are logarithmically distributed between 0.1ms and 500ms
        this.queueWaitTimer = Timer.builder(METRIC_PREFIX + "queue_wait_seconds")
                .description("Time tasks spend waiting in queue before being dispatched to a worker")
                .publishPercentileHistogram()
                .minimumExpectedValue(Duration.ofNanos(100_000))   // 0.1ms
                .maximumExpectedValue(Duration.ofMillis(500))      // 500ms
                .register(Metrics.globalRegistry);
  
        this.queueLengthGauge = Gauge.builder(METRIC_PREFIX + "queue_length", queueLength::get)
                .description("Number of tasks queued but not yet completed")
                .register(Metrics.globalRegistry);

        LOGGER.info("ComputePoolService initialized with pool size: {}", poolSize);
    }

    /**
     * Queues a blocking task for execution on the compute worker pool.
     * <p>
     * Thread-safety: This method can be safely called from multiple threads concurrently.
     *
     * @param <T>      the result type
     * @param callable the blocking task to execute
     * @return a Future that completes with the task result
     */
    public <T> Future<T> executeBlocking(Callable<T> callable) {
        final long queuedAt = System.nanoTime();
        queueLength.incrementAndGet();

        return workerExecutor.<T>executeBlocking(() -> {
            try {
                final long dispatchedAt = System.nanoTime();
                queueWaitTimer.record(dispatchedAt - queuedAt, TimeUnit.NANOSECONDS);

                return callable.call();
            } finally {  
                queueLength.decrementAndGet();
            }
        });
    }

    /**
     * Queues a blocking task that doesn't return a value.
     *
     * @param runnable the blocking task to execute
     * @return a Future that completes when the task finishes
     */
    public Future<Void> executeBlocking(Runnable runnable) {
        return executeBlocking(() -> {
            runnable.run();
            return null;
        });
    }


    /**
     * Returns the current queue length (tasks queued but not yet completed).
     */
    public long getQueueLength() {
        return queueLength.get();
    }

    public void close() {
        if (workerExecutor != null) {
            workerExecutor.close();
            LOGGER.info("ComputePoolService closed");
        }
    }
}
