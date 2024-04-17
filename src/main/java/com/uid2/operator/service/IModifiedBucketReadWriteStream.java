package com.uid2.operator.service;

import io.vertx.core.AsyncResult;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.streams.Pipe;
import io.vertx.core.streams.ReadStream;
import io.vertx.core.streams.WriteStream;

public interface IModifiedBucketReadWriteStream extends ReadStream<Buffer>, WriteStream<Buffer> {
    IModifiedBucketReadWriteStream exceptionHandler(Handler<Throwable> handler);

    Future<Void> write(Buffer buffer);

    void write(Buffer buffer, Handler<AsyncResult<Void>> handler);

    void end(Handler<AsyncResult<Void>> handler);

    WriteStream<Buffer> setWriteQueueMaxSize(int i);

    boolean writeQueueFull();

    WriteStream<Buffer> drainHandler(Handler<Void> handler);

    ReadStream<Buffer> handler(Handler<Buffer> handler);

    ReadStream<Buffer> pause();

    ReadStream<Buffer> resume();

    ReadStream<Buffer> fetch(long l);

    ReadStream<Buffer> endHandler(Handler<Void> handler);

    @Override
    default Pipe<Buffer> pipe() {
        return ReadStream.super.pipe();
    }

    @Override
    default Future<Void> pipeTo(WriteStream<Buffer> dst) {
        return ReadStream.super.pipeTo(dst);
    }

    @Override
    default void pipeTo(WriteStream<Buffer> dst, Handler<AsyncResult<Void>> handler) {
        ReadStream.super.pipeTo(dst, handler);
    }
}
