package com.uid2.operator.service;

import com.uid2.shared.Utils;
import io.vertx.core.AsyncResult;
import io.vertx.core.Context;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.streams.ReadStream;
import io.vertx.core.streams.WriteStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;


public class ModifiedBucketEncodeStream implements IModifiedBucketReadWriteStream {
    private static final Logger LOGGER = LoggerFactory.getLogger(ModifiedBucketEncodeStream.class);

    private final Context context;

    private Handler<Void> endHandler;
    private Handler<Buffer> dataHandler;
    private Handler<Void> drainHandler; // used by pipe

    private boolean readInProgress;
    private boolean incomingStreamEnded = false;
    private boolean outgoingStreamEnded = false;
    private long maxBufferSizeBytes = 5242880; // 5 MB
    private long demand = Long.MAX_VALUE;

    Buffer data;

    public ModifiedBucketEncodeStream(Context context) {
        this.context = context;
        this.data = Buffer.buffer();
    }

    @Override
    public synchronized IModifiedBucketReadWriteStream exceptionHandler(Handler<Throwable> handler) {
        return this;
    }

    @Override
    public synchronized Future<Void> write(Buffer buffer) {
        synchronized (this) {
            data.appendBuffer(buffer);
        }
        return Future.succeededFuture();
    }

    @Override
    public synchronized void write(Buffer buffer, Handler<AsyncResult<Void>> handler) {
        synchronized (this) {
            data.appendBuffer(buffer);
        }
        succeededAsyncResult(handler);
    }

    @Override
    public synchronized void end(Handler<AsyncResult<Void>> handler) {
        this.incomingStreamEnded = true;
        succeededAsyncResult(handler);
    }

    @Override
    public synchronized WriteStream<Buffer> setWriteQueueMaxSize(int i) {
        maxBufferSizeBytes = i;
        return this;
    }

    @Override
    public synchronized boolean writeQueueFull() {
        return data.length() > maxBufferSizeBytes;
    }

    @Override
    public synchronized WriteStream<Buffer> drainHandler(Handler<Void> handler) {
        this.drainHandler = handler;
        return this;
    }

    // ReadStream methods

    @Override
    public synchronized ReadStream<Buffer> handler(Handler<Buffer> handler) {
        this.dataHandler = handler;
        if (handler != null && demand > 0) {
            read();
        }
        return this;
    }

    @Override
    public synchronized ReadStream<Buffer> pause() {
        this.demand = 0;
        return this;
    }

    @Override
    public synchronized ReadStream<Buffer> resume() {
        fetch(Long.MAX_VALUE);
        return this;
    }

    @Override
    public synchronized ReadStream<Buffer> fetch(long amount) {
        demand = Long.MAX_VALUE - amount >= demand ? demand + amount : Long.MAX_VALUE;
        read();
        return this;
    }

    @Override
    public synchronized ReadStream<Buffer> endHandler(Handler<Void> handler) {
        this.endHandler = handler;
        return this;
    }

    private synchronized void read() {
        if (this.readInProgress) {
            if (!incomingStreamEnded || !outgoingStreamEnded) {
                this.context.runOnContext(v -> this.read());
            }
            return;
        }

        if (demand <= 0) {
            return;
        }
        demand--;

        this.readInProgress = true;

        this.context.executeBlocking(() -> {
            String chunk = "";
            if (data.length() == 0) {
                return chunk;
            }
            synchronized (this) {
                if (data.length() % 3 == 0 || incomingStreamEnded) {
                    chunk = Utils.toBase64String(data.getBytes());
                    data = Buffer.buffer();
                } else if ((data.length() - 1) % 3 == 0) {
                    chunk = Utils.toBase64String(Arrays.copyOfRange(data.getBytes(), 0, data.length() - 1));
                    data = Buffer.buffer(Arrays.copyOfRange(data.getBytes(), data.length() - 1, data.length()));
                } else {
                    chunk = Utils.toBase64String(Arrays.copyOfRange(data.getBytes(), 0, data.length() - 2));
                    data = Buffer.buffer(Arrays.copyOfRange(data.getBytes(), data.length() - 2, data.length()));
                }

                if(incomingStreamEnded) {
                    outgoingStreamEnded = true;
                }
            }
            return chunk;
        }, asyncResult -> {
            this.dataHandler.handle(Buffer.buffer(asyncResult.result()));
            this.readInProgress = false;
            scheduleNextRead();
        });
    }

    private synchronized void scheduleNextRead() {
        if (demand > 0 && (!incomingStreamEnded || !outgoingStreamEnded)) {
            context.runOnContext(unused -> read());
        } else if (outgoingStreamEnded && endHandler != null) {
            endHandler.handle(null);
        }
    }
}
