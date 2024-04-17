package com.uid2.operator.service;

import com.uid2.shared.encryption.Random;
import io.vertx.core.AsyncResult;
import io.vertx.core.Context;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.streams.ReadStream;
import io.vertx.core.streams.WriteStream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;


public class ModifiedBucketEncryptStream implements IModifiedBucketEncryptStream {
    private static final Logger LOGGER = LoggerFactory.getLogger(ModifiedBucketEncryptStream.class);

    private final Context context;

    private Handler<Throwable> exceptionHandler;
    private Handler<Void> endHandler;
    private Handler<Buffer> dataHandler;
    private Handler<Void> drainHandler;

    private boolean readInProgress;
    private boolean wroteStart = false;
    private boolean incomingStreamEnded = false;
    private boolean outgoingStreamEnded = false;
    private long maxBufferSizeBytes = 5242880;
    private long demand = Long.MAX_VALUE;

    Buffer data;

    final String cipherScheme = "AES/GCM/NoPadding";
    final int GCM_AUTHTAG_LENGTH = 16;
    final int GCM_IV_LENGTH = 12;
    final SecretKey k;
    final byte[] nonce;
    final Cipher c = Cipher.getInstance(cipherScheme);
    final byte[] ivBytes = Random.getBytes(GCM_IV_LENGTH);
    GCMParameterSpec gcmParameterSpec;

    public ModifiedBucketEncryptStream(Context context, byte[] encryptionKey, byte[] nonce) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        this.context = context;
        this.data = Buffer.buffer();
        this.k = new SecretKeySpec(encryptionKey, "AES");
        this.nonce = nonce;
        this.gcmParameterSpec = new GCMParameterSpec(GCM_AUTHTAG_LENGTH * 8, ivBytes);
        c.init(Cipher.ENCRYPT_MODE, k, gcmParameterSpec);
    }

    @Override
    public synchronized IModifiedBucketEncryptStream exceptionHandler(Handler<Throwable> handler) {
        this.exceptionHandler = handler;
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

    private void succeededAsyncResult(Handler<AsyncResult<Void>> handler) {
        handler.handle(new AsyncResult<Void>() {
            @Override
            public Void result() {
                return null;
            }

            @Override
            public Throwable cause() {
                return null;
            }

            @Override
            public boolean succeeded() {
                return true;
            }

            @Override
            public boolean failed() {
                return false;
            }
        });
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

    private void read() {
        if (this.readInProgress) {
            if ((!incomingStreamEnded || !outgoingStreamEnded)) {
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
            Buffer chunk = Buffer.buffer();
            if (data.length() == 0) {
                return chunk;
            }

            if (!wroteStart) {
                chunk.appendBytes(ivBytes);
                Buffer b = Buffer.buffer();
                b.appendLong(EncodingUtils.NowUTCMillis().toEpochMilli());
                b.appendBytes(this.nonce);
                chunk.appendBytes(c.update(b.getBytes()));
                wroteStart = true;
            }

            synchronized (this) {
                if (!incomingStreamEnded) {
                    chunk.appendBytes(c.update(data.getBytes()));
                    LOGGER.info(data.toString());
                    data = Buffer.buffer();
                } else {
                    chunk.appendBytes(c.doFinal(data.getBytes()));
                    data = Buffer.buffer();
                    LOGGER.info(data.toString());
                    outgoingStreamEnded = true;
                }
                return chunk;
            }
        }, asyncResult -> {
            this.dataHandler.handle(asyncResult.result());
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
