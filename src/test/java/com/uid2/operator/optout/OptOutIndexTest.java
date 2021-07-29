// Copyright (c) 2021 The Trade Desk, Inc
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

package com.uid2.operator.optout;

// @RunWith(VertxUnitRunner.class)
public class OptOutIndexTest {
    // private Vertx vertx;
    /*
    @Before
    public void setup(TestContext context) {
        vertx = Vertx.vertx();
        vertx.deployVerticle(OptOutIndex.class.getName(), context.asyncAssertSuccess());
    }

    @After
    public void tearDown(TestContext context) {
        vertx.close(context.asyncAssertSuccess());
    }

    @Test
    public void whenCreated_verifyUnhealthy(TestContext context) {
        context.assertFalse(OptOutIndex.instance.isHealthy(Instant.now()));
    }

    @Test
    public void whenUpdatedEmptyLogs_verifyUnhealthy(TestContext context) {
        String emptyLog = TestUtils.newLogFile();
        IndexUpdateMessage ium = new IndexUpdateMessage();
        ium.addDeltaFile(emptyLog);
        this.verifySuccessIndexUpdate(context, ium).onComplete(ar -> {
            context.assertFalse(OptOutIndex.instance.isHealthy(Instant.now()));
        });
    }

    @Test
    public void whenUpdatedNonEmptyLogs_verifyHealthy(TestContext context) {
        String newLog = TestUtils.newLogFile(1, 2, 3);
        IndexUpdateMessage ium = new IndexUpdateMessage();
        ium.addDeltaFile(newLog);
        this.verifySuccessIndexUpdate(context, ium).onComplete(ar -> {
            context.assertTrue(OptOutIndex.instance.isHealthy(Instant.now()));
        });
    }

    @Test
    public void whenReceivedEmptyMessage_thenSuccess(TestContext context) {
        this.verifySuccessIndexUpdate(context, IndexUpdateMessage.EMPTY);
    }

    @Test
    public void whenReceivedEmptyLogFile_thenSuccess(TestContext context) {
        String emptyLog = TestUtils.newLogFile();
        IndexUpdateMessage ium = new IndexUpdateMessage();
        ium.addDeltaFile(emptyLog);
        this.verifySuccessIndexUpdate(context, ium);
    }

    @Test
    public void whenReceivedEmptyLogFiles_thenSuccess(TestContext context) {
        String emptyLog1 = TestUtils.newLogFile();
        String emptyLog2 = TestUtils.newLogFile();
        IndexUpdateMessage ium = new IndexUpdateMessage();
        ium.addDeltaFile(emptyLog1);
        ium.addDeltaFile(emptyLog2);
        this.verifySuccessIndexUpdate(context, ium);
    }

    @Test
    public void whenReceivedOneLogFile_thenFoundEntries(TestContext context) {
        long now = OptOutUtils.nowEpochSeconds();
        OptOutEntry[] entries = TestUtils.toEntries(1, 2, 3);
        String logFile = TestUtils.newLogFile(entries);
        IndexUpdateMessage ium = new IndexUpdateMessage();
        ium.addDeltaFile(logFile);

        Async async = context.async();
        this.verifySuccessIndexUpdate(context, ium).onComplete(v -> {
            // verify entries in the log file return valid timestamp
            for (OptOutEntry e : entries) {
                long ts = OptOutIndex.instance.getOptOutTimestamp(e.identityHash);
                context.assertTrue(ts >= now);
            }

            // verify these entries return -1
            for (OptOutEntry e : TestUtils.toEntries(4, 5, 6)) {
                long notExists = OptOutIndex.instance.getOptOutTimestamp(e.identityHash);
                context.assertTrue(-1 == notExists);
            }

            // add healthy check
            context.assertTrue(OptOutIndex.instance.isHealthy(Instant.now()));
            async.complete();
        });
    }

    @Test
    public void whenReceivedLogFiles_thenFoundEntries(TestContext context) {
        Async async = context.async();
        long now = OptOutUtils.nowEpochSeconds();

        IndexUpdateMessage ium = new IndexUpdateMessage();
        ium.addDeltaFile(TestUtils.newLogFile(1, 3, 2));
        ium.addDeltaFile(TestUtils.newLogFile(6, 5, 4));
        ium.addDeltaFile(TestUtils.newLogFile(8, 9, 7));

        this.verifySuccessIndexUpdate(context, ium, 0).onComplete(v -> {
            // verify entries in the log files return valid timestamp
            for (OptOutEntry e : TestUtils.toEntries(1, 2, 3, 4, 5, 6, 7, 8, 9)) {
                long ts = OptOutIndex.instance.getOptOutTimestamp(e.identityHash);
                context.assertTrue(ts >= now);
            }

            // verify these entries return -1
            for (OptOutEntry e : TestUtils.toEntries(10, 11, 12)) {
                long notExists = OptOutIndex.instance.getOptOutTimestamp(e.identityHash);
                context.assertTrue(-1 == notExists);
            }

            // add healthy check
            context.assertTrue(OptOutIndex.instance.isHealthy(Instant.now()));
            async.complete();
        });
    }

    @Test
    public void whenReceivedAddLogFile_thenFoundEntries(TestContext context) {
        Async async = context.async();
        long now = OptOutUtils.nowEpochSeconds();

        // LogFile 1
        OptOutEntry[] entries = TestUtils.toEntries(1, 2, 3);
        String logFile = TestUtils.newLogFile(entries);
        IndexUpdateMessage ium = new IndexUpdateMessage();
        ium.addDeltaFile(logFile);

        this.verifySuccessIndexUpdate(context, ium, 0).compose(v -> {
            // LogFile 2
            OptOutEntry[] moreEntries = TestUtils.toEntries(4, 5, 6);
            String logFile2 = TestUtils.newLogFile(moreEntries);
            ium.reset();
            ium.addDeltaFile(logFile2);

            return this.verifySuccessIndexUpdate(context, ium, 1);
        }).onComplete(v -> {
            // verify entries in the log file return valid timestamp
            for (OptOutEntry e : TestUtils.toEntries(1, 2, 3, 4, 5, 6)) {
                long ts = OptOutIndex.instance.getOptOutTimestamp(e.identityHash);
                context.assertTrue(ts >= now);
            }

            // verify these entries return -1
            for (OptOutEntry e : TestUtils.toEntries(7, 8, 9)) {
                long notExists = OptOutIndex.instance.getOptOutTimestamp(e.identityHash);
                context.assertTrue(-1 == notExists);
            }

            // add healthy check
            context.assertTrue(OptOutIndex.instance.isHealthy(Instant.now()));
            async.complete();
        });
    }

    @Test
    public void whenReceivedManyLogFiles_thenFoundEntries(TestContext context) {
        Async async = context.async();
        long now = OptOutUtils.nowEpochSeconds();

        List<byte[]> indexedIds = new ArrayList<>();
        Future<Void> f = Future.succeededFuture();
        for (int i = 0; i < 100; ++i) {
            final int id = i;
            f = f.compose(v -> {
                IndexUpdateMessage ium = new IndexUpdateMessage();
                ium.addDeltaFile(TestUtils.newLogFile(id));
                indexedIds.add(OptOutEntry.idHashFromLong((long) id));
                return this.verifySuccessIndexUpdate(context, ium, id);
            });
        }

        f.onComplete(v -> {
            // verify entries in the snapshot file return valid timestamp
            for (byte[] id : indexedIds) {
                long ts = OptOutIndex.instance.getOptOutTimestamp(id);
                // System.out.format("id = %d, ts = %d\n", id, ts);
                context.assertTrue(ts >= now);
            }

            // verify these entries return -1
            for (OptOutEntry e : TestUtils.toEntries(-1, -2, -3)) {
                long notExists = OptOutIndex.instance.getOptOutTimestamp(e.identityHash);
                context.assertTrue(-1 == notExists);
            }

            // add healthy check
            context.assertTrue(OptOutIndex.instance.isHealthy(Instant.now()));
            async.complete();
        });
    }

    @Test
    public void whenReceivedSnapshotFile_thenFoundEntries(TestContext context) {
        Async async = context.async();
        long now = OptOutUtils.nowEpochSeconds();

        IndexUpdateMessage ium = new IndexUpdateMessage();
        ium.addPartitionFile(TestUtils.newSnapshotFile(1, 4, 5, 6, 2, 3));

        this.verifySuccessIndexUpdate(context, ium).onComplete(v -> {
            // verify entries in the log file return valid timestamp
            for (OptOutEntry e : TestUtils.toEntries(1, 2, 3, 4, 5, 6)) {
                long ts = OptOutIndex.instance.getOptOutTimestamp(e.identityHash);
                context.assertTrue(ts >= now);
            }

            // verify these entries return -1
            for (OptOutEntry e : TestUtils.toEntries(7, 8, 9)) {
                long notExists = OptOutIndex.instance.getOptOutTimestamp(e.identityHash);
                context.assertTrue(-1 == notExists);
            }

            // add healthy check
            context.assertTrue(OptOutIndex.instance.isHealthy(Instant.now()));
            async.complete();
        });
    }

    @Test
    public void whenReceivedNewSnapshotFile1_thenFoundEntries(TestContext context) {
        Async async = context.async();
        long now = OptOutUtils.nowEpochSeconds();

        // create index with initial log
        IndexUpdateMessage ium = new IndexUpdateMessage();
        ium.addDeltaFile(TestUtils.newLogFile(1, 2, 3));

        this.verifySuccessIndexUpdate(context, ium, 0).compose(v -> {
            // update index with 1 snapshot file (without retiring the previous log)
            ium.reset();
            ium.addPartitionFile(TestUtils.newSnapshotFile(4, 5, 6));
            return this.verifySuccessIndexUpdate(context, ium, 1);
        }).onComplete(v -> {
            // verify entries in the log file return valid timestamp
            for (OptOutEntry e : TestUtils.toEntries(1, 2, 3, 4, 5, 6)) {
                long ts = OptOutIndex.instance.getOptOutTimestamp(e.identityHash);
                context.assertTrue(ts >= now);
            }

            // verify these entries return -1
            for (OptOutEntry e : TestUtils.toEntries(7, 8, 9)) {
                long notExists = OptOutIndex.instance.getOptOutTimestamp(e.identityHash);
                context.assertTrue(-1 == notExists);
            }

            // add healthy check
            context.assertTrue(OptOutIndex.instance.isHealthy(Instant.now()));
            async.complete();
        });
    }

    @Test
    public void whenReceivedNewSnapshotFile2_thenFoundEntries(TestContext context) {
        Async async = context.async();
        long now = OptOutUtils.nowEpochSeconds();

        // create index with initial log
        IndexUpdateMessage ium = new IndexUpdateMessage();
        String logFile1 = TestUtils.newLogFile(1, 2, 3);
        ium.addDeltaFile(logFile1);

        this.verifySuccessIndexUpdate(context, ium, 0).compose(v -> {
            // update index with 1 snapshot file, and it retires one of the old log file
            ium.reset();
            ium.addPartitionFile(TestUtils.newSnapshotFile(4, 5, 6));
            ium.removeDeltaFile(logFile1);
            return this.verifySuccessIndexUpdate(context, ium, 1);
        }).onComplete(v -> {
            // verify entries in the snapshot file return valid timestamp
            for (OptOutEntry e : TestUtils.toEntries(4, 5, 6)) {
                long ts = OptOutIndex.instance.getOptOutTimestamp(e.identityHash);
                context.assertTrue(ts >= now);
            }

            // verify these entries, including the entries in the old log file return -1
            for (OptOutEntry e : TestUtils.toEntries(1, 2, 3, 7, 8, 9)) {
                long notExists = OptOutIndex.instance.getOptOutTimestamp(e.identityHash);
                context.assertTrue(-1 == notExists);
            }

            // add healthy check
            context.assertTrue(OptOutIndex.instance.isHealthy(Instant.now()));
            async.complete();
        });
    }

    @Test
    public void whenReceivedNewSnapshotFile3_thenFoundEntries(TestContext context) {
        Async async = context.async();
        long now = OptOutUtils.nowEpochSeconds();

        // create index with initial log of 2
        IndexUpdateMessage ium = new IndexUpdateMessage();
        String logFile1 = TestUtils.newLogFile(1, 2, 3);
        ium.addDeltaFile(logFile1);
        ium.addDeltaFile(TestUtils.newLogFile(4, 5, 6));

        this.verifySuccessIndexUpdate(context, ium, 0).compose(v -> {
            // update index with 1 snapshot file, and it retires 1 of the old log file
            // plus a new log file
            ium.reset();
            ium.addPartitionFile(TestUtils.newSnapshotFile(7, 8, 9));
            ium.addDeltaFile(TestUtils.newLogFile(10, 11, 12));
            ium.removeDeltaFile(logFile1);
            return this.verifySuccessIndexUpdate(context, ium, 1);
        }).onComplete(v -> {
            // verify entries in the snapshot file return valid timestamp
            for (OptOutEntry e : TestUtils.toEntries(4, 5, 6, 7, 8, 9, 10, 11, 12)) {
                long ts = OptOutIndex.instance.getOptOutTimestamp(e.identityHash);
                context.assertTrue(ts >= now);
            }

            // verify these entries, including the entries in the old log file return -1
            for (OptOutEntry e : TestUtils.toEntries(1, 2, 3, 13, 14, 15)) {
                long notExists = OptOutIndex.instance.getOptOutTimestamp(e.identityHash);
                context.assertTrue(-1 == notExists);
            }

            // add healthy check
            context.assertTrue(OptOutIndex.instance.isHealthy(Instant.now()));
            async.complete();
        });
    }

    @Test
    public void whenReceivedManySnapshotFiles_thenFoundEntries(TestContext context) {
        Async async = context.async();
        long now = OptOutUtils.nowEpochSeconds();

        List<Long> indexedIds = new ArrayList<>();
        Future<Void> f = Future.succeededFuture();
        for (int i = 0; i < 100; ++i) {
            final int id = i;
            f = f.compose(v -> {
                // new snapshot includes all previous ids for this test
                indexedIds.add((long) id);
                IndexUpdateMessage ium = new IndexUpdateMessage();
                ium.addPartitionFile(TestUtils.newSnapshotFile(indexedIds));

                return this.verifySuccessIndexUpdate(context, ium, id);
            });
        }

        f.onComplete(v -> {
            // verify entries in the snapshot file return valid timestamp
            for (long id : indexedIds) {
                byte[] hashBytes = OptOutEntry.idHashFromLong(id);
                long ts = OptOutIndex.instance.getOptOutTimestamp(hashBytes);
                // System.out.format("id = %d, ts = %d\n", id, ts);
                context.assertTrue(ts >= now);
            }

            // verify these entries return -1
            for (OptOutEntry e : TestUtils.toEntries(-1, -2, -3)) {
                long notExists = OptOutIndex.instance.getOptOutTimestamp(e.identityHash);
                context.assertTrue(-1 == notExists);
            }

            // add healthy check
            context.assertTrue(OptOutIndex.instance.isHealthy(Instant.now()));
            async.complete();
        });
    }

    private Future<Void> verifySuccessIndexUpdate(TestContext context, IndexUpdateMessage ium) {
        return verifySuccessIndexUpdate(context, ium, 0);
    }

    private Future<Void> verifySuccessIndexUpdate(TestContext context, IndexUpdateMessage ium, int iteration) {
        Promise<Void> promise = Promise.promise();
        Async async = context.async();

        MessageConsumer<Integer> c = vertx.eventBus().consumer(Event.IndexUpdated);
        c.handler(m -> {
            int i = (int) m.body();
            context.assertEquals(iteration, i);
            c.unregister(); // unregister this consumer once validation is done
            async.complete();
            promise.complete();
        });

        vertx.eventBus().send(Event.IndexUpdate, ium.toJsonString());
        return promise.future();
    }
     */
}
