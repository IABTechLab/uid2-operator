package com.uid2.operator.service;

import com.uid2.shared.model.SaltEntry;
import io.vertx.core.*;
import io.vertx.core.AsyncResult;
import io.vertx.core.Context;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.streams.Pipe;
import io.vertx.core.streams.ReadStream;
import io.vertx.core.streams.WriteStream;

import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class ModifiedBucketReadStream implements ReadStream<Buffer> {
    private static final Logger LOGGER = LoggerFactory.getLogger(ModifiedBucketReadStream.class);
    private static final DateTimeFormatter APIDateTimeFormatter = DateTimeFormatter.ISO_LOCAL_DATE_TIME.withZone(ZoneId.of("UTC"));

    private final Context context;

    private Handler<Buffer> dataHandler;
    private Handler<Void> endHandler;

    private boolean readInProgress;
    private boolean wroteStart = false;
    private boolean streamEnded = false;
    private long demand = Long.MAX_VALUE;
    private final int chunkSize;

    private final List<SaltEntry> modified;

    public ModifiedBucketReadStream(Context context, List<SaltEntry> modified, int chunkSize) {
        this.context = context;
        this.modified = modified;
        this.chunkSize = chunkSize;
    }

    private String makeSaltEntriesString() {
        StringBuilder s = new StringBuilder();
        for (int i = 0; i < chunkSize && i < modified.size(); i++) {
            SaltEntry e = modified.remove(0);
            s.append("{\"bucket_id\":\"")
                    .append(e.getHashedId())
                    .append("\",\"last_updated\":\"")
                    .append(APIDateTimeFormatter.format(Instant.ofEpochMilli(e.getLastUpdated())))
                    .append("\"},");
        }
        return s.toString();
    }

    @Override
    public synchronized ReadStream<Buffer> exceptionHandler(Handler<Throwable> handler) {
        return this;
    }

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

    private void read() {
        if (this.readInProgress) {
            if (!streamEnded && !modified.isEmpty()) {
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
            StringBuilder salts = new StringBuilder();

            if (!wroteStart) {
                salts.append("{\"body\":[");
                wroteStart = true;
            }

            salts.append(makeSaltEntriesString());

            if (modified.isEmpty()) {
                salts.deleteCharAt(salts.length() - 1); // remove trailing comma
                salts.append("],\"status\":\"success\"}");
                streamEnded = true;
            }
            return salts.toString();
        }, asyncResult -> {
            this.dataHandler.handle(Buffer.buffer(asyncResult.result().getBytes()));
            this.readInProgress = false;
            scheduleNextRead();
        });
    }

    private synchronized void scheduleNextRead() {
        if (demand > 0 && !streamEnded) {
            context.runOnContext(unused -> read());
        } else if (streamEnded && endHandler != null) {
            endHandler.handle(null);
        }
    }
}
